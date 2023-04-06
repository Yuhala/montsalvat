/*
 * Created on Wed Sep 09 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */
package iiun.smartc;

import iiun.smartc.*;
import org.graalvm.nativeimage.SecurityInfo;
import org.graalvm.nativeimage.SGXObjectTranslator;
import java.util.ArrayList;
import java.util.HashMap;

@SecurityInfo(security = "trusted")
public class Contract {
    /**
     * We will invoke an untrusted routine called "subtract" defined in the untrusted
     * runtime. So we import the associated proxy method which we will call to
     * perform the enclave transition.
     * 
     */

    //private int ledgerHash;
    private HashMap<Integer, Asset> ledger;
    private int contractId;
    private String name;

    public Contract(int cId) {
        this.contractId = cId;
		this.name = getRandStringT(8);
    }


    static int countNulls() {
        System.gc();
		int num = SGXObjectTranslator.getNullMirrors();
		System.out.println("======= Number of null mirrors: " + num + " =========");
		return num;
	}

	static int countMirrors() {
		int num = SGXObjectTranslator.getNumMirrors();
		// System.out.println("======= Size of mirror registry: " + num + " =========");

		// int num2 = SGXObjectTranslator.getNumWeakRefs();
		// System.out.println("======= Size of weak ref registry: " + num2 +
		// "==========");
		return num;
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

    static void ledger_init() {
        System.out.println("In ledger init");
        Contract c1 = new Contract(123);
        c1.initLedger();
        // c1.transferAsset(001, 111, 112);
        // c1.transferAsset(002, 112, 113);

        int a = 55;
        int b = 35;
        int diff = b - a;
        System.out.println("The calculated difference is: " + diff);

        System.out.println("Initialized ledger with dummy assets");

        Peer peer1 = new Peer("xxx", 666);

        // this should do an automatic ocall
        // Peer p0 = new Peer(1234);
        // Peer p1 = new Peer(1234);
        // p0.sayHello();
        // make eligible for gc
        // p0 = null;
        // p1 = null;

    }

    public void greetPerson(Person p) {
        System.out.println("Contract greeting person: " + p.getPersonId());
    }

    public void greetPeer(Peer p) {
        System.out.println("Contract greeting peer: " + p.getPeerId());
    }

    static int add(int a, int b) {
        System.out.println("Contract add");
        return (a + b);

    }

    static String sendGreetings() {
        String str = "Contract greetings";
        return str;

    }

    static void hello(String name) {
        System.out.println("Contract:Hello: " + name);
    }

    /**
     * Initialize ledger with dummy assets
     */
    public void initLedger() {

        // create Asset objects
        Asset asset1 = new Asset(001, 111, 100);
        Asset asset2 = new Asset(002, 112, 100);
        Asset asset3 = new Asset(003, 113, 100);
        Asset asset4 = new Asset(004, 114, 100);

        // add Asset objects in ledger
        ledger = new HashMap<Integer, Asset>();
        ledger.put(001, asset1);
        ledger.put(002, asset2);
        ledger.put(003, asset3);
        ledger.put(004, asset4);

    }

    public void getAsset(int aId) {
        // pring all asset info
        // TODO
        System.out.println("Asset name: " + aId);
    }

    // Tests serializable object params
    public void transferAsset(Asset asset, int buyerId, int sellerId) {
        // modify owners in ledger
        // TODO
        System.out.println("Transfered asset: " + asset.getAssetId() + " from: " + sellerId + " to: " + buyerId);
        // System.out.println("Transfered asset btw 2 peers");
    }
}
