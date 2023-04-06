/*
 * Created on Wed Sep 09 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

package iiun.smartc;

import java.util.ArrayList;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "trusted")
public class Peer {
    private static int id = 0;
    public int balance;
    private int ledgerHash;
    private String peerName;

    public Peer(String name, int balance) {
        this.balance = balance;
        this.ledgerHash = 12345;
        this.peerName = name;
        id++;
        System.out.println("Created peer: Name- " + this.peerName);
        Person per = new Person("peer person proxy");
        System.out.println("Created person proxy in peer constructor");
    }

    public void sayMyName(String name) {

        System.out.println("My peer-name is: " + name);
    }

    public void stringTest(String s, int i) {
        System.out.println("StringTest:: s is:" + s + " i is: " + i);
    }

    public int getPeerId() {
        return id;
    }

    public String getName() {
        return this.peerName;
    }

    public int getBalance() {
        return this.balance;
    }

    public void setBalance(int bal) {
        this.balance = bal;
    }

    public int getLedgerHash() {
        return ledgerHash;
    }

    public void setLedgerhash(int hash) {
        this.ledgerHash = hash;
    }

    /**
     * This is a method to test correct serialization/deserialization of object
     * types
     */
    public void addAssets(ArrayList<Integer> list) {
        for (int id : list) {
            System.out.println("Added asset id: " + id);
        }
    }

    public void sayHello() {
        System.out.println("Hello I'm a peer with balance: " + this.balance);

    }
}
