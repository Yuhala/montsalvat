
/*
 * Created on Sun May 16 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */


package iiun.smartc;

import java.util.ArrayList;

import org.graalvm.nativeimage.SGXObjectTranslator;
import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "trusted")
public class Secure {
	private int id;
	// random
	private String name;
	public static int numInv = 10000;

	public Trusted(int n) {
		this.id = n;
		this.name = getRandStringT(8);
	}

	public void setNameT(String str) {
		this.name = str;
	}

	// https://www.geeksforgeeks.org/generate-random-string-of-given-size-in-java/
	public static String getRandStringT(int length) {
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

	public static void doGCInside() {
		System.out.println(">>>>>>>>>>>>>>> Doing GC in <<<<<<<<<<<<<<<<<<");
		int num = 0;// SGXObjectTranslator.getNullMirrors();
		// System.out.println("======= Number of null mirrors before GC: " + num + "
		// =========");
		System.gc();

		// Thread.sleep(500);

	}

	public static int getNulls() {
		int num = SGXObjectTranslator.getNullMirrors();
		System.out.println("======= Number of null mirrors: " + num + " =========");
		return num;
	}

	public static int getMirros() {
		int num = SGXObjectTranslator.getNumMirrors();
		// System.out.println("======= Size of mirror registry: " + num + " =========");

		// int num2 = SGXObjectTranslator.getNumWeakRefs();
		// System.out.println("======= Size of weak ref registry: " + num2 +
		// "==========");
		return num;
	}

	/**
	 * Its makes more sense as a static method, but done this way for benchmarking
	 * purposes :)
	 * 
	 * @param l
	 */
	public void setNamesT(int n) {
		Trusted obj = new Trusted(0);
		for (int i = 0; i < n; i++) {
			String str = "randomm" + i;
			obj.setNameT(str);
		}
	}

	/** Here obj is a proxy and will go outside n times with the list as param */
	public static void proxyIn(int n) {
		Untrusted obj = new Untrusted(0);
		StopWatch clock = new StopWatch();
		clock.start();
		for (int i = 0; i < numInv; i++) {
			obj.setNamesU(n);
		}
		double total = clock.stop();
		System.out.println(">>>>>>>>>>>>>>> Total time proxyIn: " + total);
		ResultsWriter.write(Double.toString(total));
	}

	/**
	 * Here obj is concrete and will not do all invocations inside with the list as
	 * param
	 */
	public static void concreteIn(ArrayList<String> l) {
		Trusted obj = new Trusted(0);
		StopWatch clock = new StopWatch();
		clock.start();
		for (int i = 0; i < numInv; i++) {
			// obj.setNamesT(l);
		}
		double total = clock.stop();
		System.out.println(">>>>>>>>>>>>>>> Total time concreteIn: " + total);
		ResultsWriter.write(Double.toString(total));
	}
}
