
/*
 * Created on Sun May 16 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package iiun.smartc;

import iiun.smartc.*;
import java.util.ArrayList;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "untrusted")
public class Untrusted {
	private int id;
	// random string
	private String name;

	public Untrusted(int n) {
		this.id = n;
		this.name = getRandStringU(32);
	}

	public void setNameU(String str) {
		this.name = str;
	}

	public void setNamesU(int n) {
		Untrusted obj = new Untrusted(0);
		for (int i = 0; i < n; i++) {
			String str = "randomm"+i;
			obj.setNameU(str);
		}
	}

	// https://www.geeksforgeeks.org/generate-random-string-of-given-size-in-java/
	public static String getRandStringU(int length) {
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
}
