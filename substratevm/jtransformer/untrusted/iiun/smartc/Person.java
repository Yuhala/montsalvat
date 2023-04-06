/*
 * Created on Wed Sep 09 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

package iiun.smartc;

import java.util.ArrayList;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "untrusted")
public class Person {
    private static int id = 0;
    private String name;

    public Person(String name) {
        this.name = name;
        id++;
    }

    public void sayMyName(String name) {

        System.out.println("Person name is: " + name);
    }

    public int getPersonId() {
        return id;
    }

    public String getName() {
        return this.name;
    }

    public void setId(int n){
        this.id = n;
    }

}
