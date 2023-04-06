/*
 * Created on Wed Sep 09 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */
package iiun.smartc;

import org.graalvm.nativeimage.SecurityInfo;
import java.io.Serializable;

//@SecurityInfo(security = "untrusted")
public class Asset implements Serializable{
    private int assetId;
    private int assetOwner;
    private int assetPrice;

    public Asset(int id, int owner, int price) {
        this.assetId = id;
        this.assetOwner = owner;
        this.assetPrice = price;
        System.out.println("Created asset: " + id);
        // System.out.println("Create asset");
    }

    public int getAssetId() {
        return assetId;
    }

   

}
