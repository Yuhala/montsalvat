/*
 * Created on Mon Mar 22 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package com.linkedin.paldb;

import com.linkedin.paldb.api.Configuration;
import com.linkedin.paldb.api.PalDB;
import com.linkedin.paldb.api.StoreReader;
import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.LogManager;
import org.graalvm.nativeimage.SecurityInfo;
import java.nio.file.Paths;
//import java.util.Random;
//import org.apache.commons.lang.RandomStringUtils;

@SecurityInfo(security = "untrusted")
public class BenchMain {

  public static final String storeFile = Paths.get("").toAbsolutePath().toString()
      + "/paldb/data/store.paldb";
  public static final int MAX_KEY_COUNT = 100_000;

  /** Measure time for n reads and writes */
  static void readWrite(int numKeys) {
    // cleanup(new File(storeFile));

    // int numKeys = 10_000;
    int numReads = 10_000;
    int mult = 10_000;
    int numRuns = 1;
    double totalTime;

    DBWriter writer = new DBWriter(numKeys, storeFile);
    DBReader reader = new DBReader(numKeys, storeFile);

    double writeTime = writer.writeStore(numKeys);

    double readTime = reader.readStore(numKeys);

    // print results
    System.out.println("Write time: " + writeTime);
    System.out.println("Read time: " + readTime);

    // for better precision double additions
    BigDecimal w = new BigDecimal(writeTime);
    BigDecimal r = new BigDecimal(readTime);
    BigDecimal total = w.add(r);

    System.out.println("Num keys in index: " + numKeys);
    System.out.println("Total R/W time (Double.sum): " + Double.sum(writeTime, readTime));
    System.out.println("Total R/W time (BigDecimal.add): " + total);

    //ResultsWriter.write(total.toString());

    // System.gc();
    cleanup(new File(storeFile));
    // numKeys += mult;

  }

  static void cleanup(File dbFile) {
    dbFile.delete();
  }

  public static void main(String[] args) {
    // Disable logger
    LogManager.getLogManager().reset();

    // app name not part of args
    int numKeys = Integer.parseInt(args[0]);

    readWrite(numKeys);
  }
}
