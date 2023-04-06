/*
 * Created on Mon Apr 12 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package com.linkedin.paldb;

import com.linkedin.paldb.api.Configuration;
import com.linkedin.paldb.api.PalDB;
import com.linkedin.paldb.api.StoreWriter;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.LogManager;
import com.linkedin.paldb.StopWatch;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "untrusted")
public class DBWriter {

  //"/home/petman/projects/graal-tee/substratevm/paldb/data/store.paldb";
  private static String storeFile;
  public static final int VAL_LEN = 128;
  public static Integer[] keys;
  public static final int seed = 123456789;

  private static final int MAX_KEY_COUNT = 100_000;

  public DBWriter(int numKeys, String file) {
    storeFile = file;
    //Generates random keys to be written
    keys = writerIntGenerator(seed, Integer.MAX_VALUE, numKeys); //GenerateTestData.generateRandomIntKeys(keysCount, Integer.MAX_VALUE, seed);
  }

  public double writeStore(int numWrites) {
    int valueLength = VAL_LEN;
    assert (numWrites <= keys.length) : "number of writes larger than number of keys in db";
    Configuration config = PalDB.newConfiguration();
    //config.set(Configuration.CACHE_ENABLED, "true");
    //config.set(Configuration.COMPRESSION_ENABLED, "false");

    //StoreReader reader = PalDB.createReader(new File("store.paldb"), config);

    //RandomStringUtils.randomAlphabetic(valueLength);
    StoreWriter writer = PalDB.createWriter(new File(storeFile), config);

    //Calculate time to write kv pairs in db
    StopWatch clock = new StopWatch();    
    clock.start();  
    

    for (int i = 0; i < numWrites; i++) {
      if (valueLength == 0) {
        writer.put(keys[i].toString(), Boolean.TRUE);
      } else {
        writer.put(keys[i].toString(), getRandString(valueLength));
      }
    }
    
    writer.close();

    return clock.stop();
  }

  

  static void writerCleanup(File dbFile) {
    dbFile.delete();
  }

  //https://www.geeksforgeeks.org/generate-random-string-of-given-size-in-java/
  public static String getRandString(int length) {
    // chose a Character random from this String
    String AlphaNumericString =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";

    // create StringBuffer size of AlphaNumericString
    StringBuilder sb = new StringBuilder(length);

    for (int i = 0; i < length; i++) {
      // generate a random number between
      // 0 to AlphaNumericString variable length
      int index = (int) (AlphaNumericString.length() * Math.random());

      // add Character one by one in end of sb
      sb.append(AlphaNumericString.charAt(index));
    }

    return sb.toString();
  }

  /**New pseudo-random num generator to avoid graal native image java.util.Random build issues
   * pyuhala
   */
  static Integer[] writerIntGenerator(int seed, int range, int count) {
    //We use the linear congruential method
    int multiplier = 3;
    Integer[] randomInts = new Integer[count];
    randomInts[0] = seed;
    for (int i = 1; i < count; i++) {
      randomInts[i] = ((randomInts[i - 1] * multiplier) + 987654321) % range;
    }

    return randomInts;
  }
}
