
/*
 * Created on Mon Jul 06 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/**
 * This is a sample (dummy) smart contract application for transfering assets between peers.
 * I use this to reason out clearly about code separation into trusted and untrusted parts.
 */

package iiun.smartc;

import java.util.ArrayList;
import iiun.smartc.*;
//import iiun.smartc.Trusted;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;

import javax.naming.spi.DirStateFactory.Result;

import org.graalvm.nativeimage.SecurityInfo;
import org.graalvm.nativeimage.SGXSerializer;
import org.graalvm.nativeimage.ProxyCleaner;
import org.graalvm.nativeimage.SGXObjectTranslator;

@SecurityInfo(security = "untrusted")
public class Main {

	// public static HashMap<Integer, CCharPointer> myMap = new HashMap<>();
	public static HashMap<Integer, Contract> gcObjects = new HashMap<>();
	// Number of method invocations
	public static int numInv = 10000;

	static void gcTest(int numObjects, int strLen) {

		// Fill hashmap with int-string kv pairs
		for (int i = 0; i < numObjects; i++) {
			// String str = getRandString(strLen);
			Contract obj = new Contract(i);
			gcObjects.put(i, obj);
		}

		// Remove kv pairs from hashmap
		for (int i = 0; i < numObjects; i++) {
			gcObjects.remove(i);
		}
	}

	// https://www.geeksforgeeks.org/generate-random-string-of-given-size-in-java/
	public static String getRandString(int length) {
		// chose a Character random from this String
		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";

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

	static void doConcreteOut(ArrayList<String> l) {
		Untrusted obj = new Untrusted(0);
		StopWatch clock = new StopWatch();
		clock.start();
		for (int i = 0; i < numInv; i++) {
			// obj.setNamesU(l);
		}
		double total = clock.stop();
		System.out.println(">>>>>>>>>>>>>>> Total time concreteOut: " + total);
		// ResultsWriter.write(Double.toString(total));
	}

	static void doConcreteIn(ArrayList<String> l) {
		Trusted.concreteIn(l);
	}

	static void doProxyOut(int n) {
		Trusted obj = new Trusted(0);
		StopWatch clock = new StopWatch();
		clock.start();
		for (int i = 0; i < numInv; i++) {
			obj.setNamesT(n);
		}
		double total = clock.stop();
		System.out.println(">>>>>>>>>>>>>>> Total time proxyOut: " + total);
		// ResultsWriter.write(Double.toString(total));
	}

	static void doProxyIn(int n) {
		Trusted.proxyIn(n);
	}

	/**
	 * This method does a "crude" GC consistency test for our partitioned app. It
	 * continuously creates and destroy proxy objects (by invoking the garbage
	 * collector), and registers the number of live proxies, and the number of
	 * mirror objects in the registry in the opposite runtime (ie have not been made
	 * eligible for GC)
	 * 
	 * @param numSec
	 */
	static void doConsistencyTest(int numSec, int sleep) throws InterruptedException {
		int numMillis = numSec * 1000;
		// wait time in millis, should be larger than the GC helper period to have
		// reasonable results

		int maxObjs = 200000;
		int minObjs = 0;
		int step = 5000;
		double start = System.currentTimeMillis();
		double stop = 0.0;
		// are we decreasing objects ? if yes do gc each time, otherwise do not
		boolean down = true;

		// initialize the object registry with maxObjs
		addObjs(0, maxObjs);

		while (stop <= numMillis) {
			stop = System.currentTimeMillis() - start;
			if (down) {
				for (int i = maxObjs; i >= minObjs; i -= step) {

					removeObjs(i - step + 1, i);
					System.gc();
					double time = System.currentTimeMillis() - start;
					int numProxies = gcObjects.size();
					System.out.println(">>>>>>>>>>>>>>> Proxy: " + time + "," + numProxies);
					ResultsWriter.write(time + "," + numProxies, "proxy.csv");
					Thread.sleep(sleep);

					time = System.currentTimeMillis() - start;
					int numMirrors = Contract.countNulls();//Contract.countMirrors();
					System.out.println(">>>>>>>>>>>>>>> Mirror: " + time + "," + numMirrors);

					ResultsWriter.write(time + "," + numMirrors, "mirror.csv");

				}
			} else {
				for (int i = minObjs; i <= maxObjs; i += step) {

					addObjs(i, i + step - 1);
					double time = System.currentTimeMillis() - start;
					int numProxies = gcObjects.size();
					System.out.println(">>>>>>>>>>>>>>> Proxy: " + time + "," + numProxies);
					ResultsWriter.write(time + "," + numProxies, "proxy.csv");
					Thread.sleep(sleep);

					time = System.currentTimeMillis() - start;
					int numMirrors = Contract.countNulls();//Contract.countMirrors();
					ResultsWriter.write(time + "," + numMirrors, "mirror.csv");
					System.out.println(">>>>>>>>>>>>> Mirror: " + time + "," + numMirrors);

				}

			}
			// change direction
			down = !down;

		}

	}

	/**
	 * Remove num objects from registry
	 * 
	 * @param num
	 */
	static void removeObjs(int startIndx, int stopIndx) {
		for (int i = startIndx; i < stopIndx; i++) {
			gcObjects.remove(i);
		}
	}

	/**
	 * Add some proxies to registry
	 * 
	 * @param startIndx
	 * @param num
	 */
	static void addObjs(int startIndx, int num) {
		for (int i = startIndx; i < num; i++) {
			Contract obj = new Contract(i);
			gcObjects.put(i, obj);
		}
	}

	public static void main(String[] args) throws InterruptedException {

		//int time = Integer.parseInt(args[0]);
		//int sleep = Integer.parseInt(args[1]);
		//long gcHelperWait = Long.parseLong(args[2]);

		//ProxyCleaner.initProxyCleaners(gcHelperWait);

		//doConsistencyTest(time, sleep);
		System.out.println("------------ Hello Peterson! ---------");
		Contract c = new Contract(100);
		c.initLedger();
		c.getAsset(001);

		/*
		 * ArrayList<String> list = new ArrayList<>(); // fill the list with strings for
		 * (int i = 0; i < size; i++) { String str = getRandString(8); list.add(str); }
		 */

		// doProxyIn(size);
		// doProxyOut(size);
		// doConcreteIn(list);
		// doConcreteOut(list);

		/**
		 * Do GC out first, wait for some time, >> 1000ms, for the proxy cleaner to make
		 * mirror objects inside eligible.
		 */
		// System.out.println(">>>>>>>>>>>>>>>>>> Doing GC out <<<<<<<<<<<<<<<<<");
		// System.gc();

		// pause for 2 secs or more
		// Thread.sleep(2000);

		// System.out.println(">>>>>>>>>>>>>>>>>> B4 GC in <<<<<<<<<<<<<<<<<");
		// Trusted.getNum();
		// Trusted.getNull();

		// System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<");
		// Trusted.doGCInside();

		// System.out.println(">>>>>>>>>>>>>>>>>> After GC in <<<<<<<<<<<<<<<<<");
		// Thread.sleep(1000);

		// Trusted.getNum();
		// Trusted.getNull();

		//ProxyCleaner.stopProxyCleaners();
	}

}
