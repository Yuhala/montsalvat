/*
 * Created on Mon Apr 12 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package com.linkedin.paldb;

import com.linkedin.paldb.api.Configuration;
import com.linkedin.paldb.api.PalDB;
import com.linkedin.paldb.api.StoreReader;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.LogManager;

import com.linkedin.paldb.StopWatch;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "trusted")
public class DBReader {

  //"/home/petman/projects/graal-tee/substratevm/paldb/data/store.paldb";
  private static String storeFile;
  public static final int VAL_LEN = 8;
  Integer[] keys;

  private static final int MAX_KEY_COUNT = 100_000;
  

  public DBReader(int numReads, String file) {   

    storeFile = file;
    //Generates random keys to be read
    keys = readerIntGenerator(987654321, Integer.MAX_VALUE, numReads);
  }

  public double readStore(int numReads) {
    StoreReader reader = PalDB.createReader(new File(storeFile));


    //Generate random keys to test

    //Calculate time to read kv pairs from db
    StopWatch clock = new StopWatch();    
    clock.start();

    for (int i = 0; i < numReads; i++) {
      Integer key = keys[i];
      reader.get(key.toString());
    }  

    reader.close();

    return clock.stop();
  }

  /**Measure time for n reads only */
  static void readOnly() {
    readerCleanup(new File(storeFile));

    int numKeys = 10_000;
    int numReads = 10_000;
    int mult = 10_000;
    int numRuns = 1;
    double tput = 0;
    long readTime = 0;

   

    while (numKeys <= MAX_KEY_COUNT) {
      tput = 0;
      //bench = new BenchMain(numKeys);
      //long writeTime = bench.writeStore();

      //run the bench n times and get avg
      for (int i = 0; i < numRuns; i++) {
        //readTime = bench.readStore(numReads);
        //tput += getTput(numReads, readTime);
      }

      tput /= numRuns;

      System.out.println("Read time: " + readTime);
      System.out.println(
        "Num keys in index: " + numKeys + " Tput(Reads/s): " + tput
      );
      //System.gc();
      readerCleanup(new File(storeFile));
      //numKeys += mult;
    }
  }

  static double getTput(int numOps, long msTime) {
    double tput = numOps / msTime;
    return tput * 1000;
  }

  /**New pseudo-random num generator to avoid graal native image java.util.Random build issues
   * pyuhala
   */
  static Integer[] readerIntGenerator(int seed, int range, int count) {
    //We use the linear congruential method
    int multiplier = 3;
    Integer[] randomInts = new Integer[count];
    randomInts[0] = seed;
    for (int i = 1; i < count; i++) {
      randomInts[i] = ((randomInts[i - 1] * multiplier) + 987654321) % range;
    }

    return randomInts;
  }

  static void readerCleanup(File dbFile) {
    dbFile.delete();
  }
}
