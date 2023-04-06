/*
 * Created on Wed Jan 20 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package org.graalvm.nativeimage;

import java.util.HashMap;
import java.util.concurrent.*;

import org.graalvm.nativeimage.CurrentIsolate;
import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.SecurityInfo;
//import com.oracle.svm.core.log.Log;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

public class SGXObjectTranslator {

    /**
     * Proxy object map: the proxy objects in one runtime are responsible for
     * creating mirror objects in the opposite runtime. Each time a proxy
     * object/class method is called a transition in/out of the enclave is done and
     * the corresponding method in the opposite runtime is invoked. Upon
     * instantiantion, proxy objects are added to this map. For each object about to
     * be garbage collected, its hashcode is calculated and if it's present in this
     * map, it is destroyed/mark to be destroyed normally by the GC and a
     * corresponding enclave transition with its hashcode so the associated mirror
     * object can be garbage collected or marked for garbage collection.
     */
    private static HashMap<Integer, Object> proxyObjects = new HashMap<>();

    /**
     * Mirror object map: it contains the corresponding objects of proxy objects in
     * the opposite runtime. The GC should never destroy objects here without prior
     * permission (from the other GC via a cross enclave routine).
     */
    private static HashMap<Integer, Object> mirrorObjects = new HashMap<>();

    private static ConcurrentHashMap<Integer, Object> returnVals = new ConcurrentHashMap<>();

    /**
     * This list is used for benchmarking/testing to determine if the mirror objects
     * have been GC-ed also
     */
    private static List<WeakReference<Object>> mirrorRefs = new ArrayList<WeakReference<Object>>();

    /** Some logging messages */
    public static final String objectNotFound = "No mirror object corresponds to the proxy hashcode: ";

    /**
     * This field tells us which security family this class is part of; default =
     * true; Proxy cleaner object in unsecure runtime will set this to false
     */
    private static boolean isSecure = true;

    /** Number of proxy/mirror objects that have been created. */
    private static long numObjs = 0;

    /**
     * Perform "object translation": input the hash code of the proxy object and get
     * the corresponding object from the object registry: mirrorObjects
     */
    // @CEntryPoint(name = "getMirrorObject")
    public static Object getMirrorObject(int proxyHashCode) {
        Integer h = proxyHashCode;
        Object ret = null;
        ret = mirrorObjects.get(h);
        if (ret == null) {
            System.out.println(objectNotFound + h);
        }
        // System.out.println("Calling instance method on mirror object");
        return ret;
    }

    /**
     * Tests if the parameter object is in the mirror object registry
     * 
     * @param obj
     * @return
     */
    public static boolean isMirrorObject(Object obj) {
        boolean ret = false;
        for (Integer key : mirrorObjects.keySet()) {
            if (mirrorObjects.get(key).equals(obj)) {
                // ret = true;break
                return true;
            }
        }

        return ret;
    }

    /**
     * Returns the corresponding proxy hashcode for the mirror object
     * 
     * @param mirrorObj
     * @return
     */
    public static int getProxyHash(Object mirrorObj) {
        // TODO: find better magic num of "impossible hash"
        int ret = -123456;
        for (Integer key : mirrorObjects.keySet()) {
            if (mirrorObjects.get(key).equals(mirrorObj)) {
                // ret = key;break
                return key;
            }
        }

        return ret;
    }

    /**
     * Add an object pair to the registry: proxy object hashcode vs mirror/concrete
     * object
     */
    // @CEntryPoint(name = "putMirrorObject")
    public static void putMirrorObject(int proxyHashCode, Object mirror) {
        Integer h = proxyHashCode;
        mirrorObjects.put(h, mirror);
        // String env = isSecure ? "in" : "out";
        // System.out.println("Added mirror object for proxy: " + h);

        // Add weak ref to list
        mirrorRefs.add(new WeakReference<Object>(mirror));
        numObjs++;
        

    }

    /**
     * This method is used for benchmarking/testing to get the number of dead mirror
     * objects.
     * 
     */

    public static int getNullMirrors() {
        System.out.println("getting null mirrors");
        int count = 0;
        for (int i = 0; i < mirrorRefs.size(); i++) {
            /** get the strong ref from weak ref and test if it's null */
            System.out.println(">>>>> point 1");
            if (mirrorRefs.get(i).get() == null) {
                System.out.println(">>>>> point 2");
                count++;
                System.out.println(">>>>> point 3");
            }
        }
        int diff = mirrorRefs.size() - count;
        return diff;
    }

    public static int getNumMirrors() {
        return mirrorObjects.size();
    }

    public static int getNumWeakRefs(){
        return mirrorRefs.size();
    }

    /**
     * Remove mirror object from registry. This method is called once a proxy
     * cleaner finds a null weak ref for a proxy. An enclave transition is then done
     * to remove the corresponding mirror object from the registry.
     */

    public static void removeMirrorObject(int proxyHashCode) {
        Integer obj = proxyHashCode;
        mirrorObjects.remove(obj);
        // System.out.println("Removed mirror object from registry");
        numObjs--;

    }

    /**
     * Add a proxy object to the proxy object registry. This method will probably be
     * modified or removed. We don't want strong references to proxy objects in a
     * global registry. This will prevent them from being GC-ed.
     */
    // @CEntryPoint(name = "putProxyObject")
    public static void putProxyObject(Object proxy) {

        Integer h = hash(proxy);
        proxyObjects.put(h, proxy);
        // System.out.println("Added proxy object to registry");
    }

    public static synchronized void putReturnVal(int hash, Object val) {
        Integer h = hash;
        returnVals.put(h, val);
        System.out.println("Added return val: " + h);
    }

    public static synchronized Object getReturnVal(int hash) {
        Integer h = hash;
        System.out.println("Getting return val: " + h);
        if (returnVals.containsKey(h)) {

        } else {
            System.out
                    .println("Return registry does not contain key: " + hash + " Registry size: " + returnVals.size());
        }
        return returnVals.get(h);
    }

    public static synchronized void removeReturnVal(int hash) {
        Integer h = hash;
        returnVals.remove(h);
        System.out.println("Removing return val: " + h);
    }

    /**
     * This method should probably be synchronized. However conflicting values will
     * never be written by different objects. It will always be true or false for
     * secure or unsecure RT respectively. Strangely it cause weird issues during
     * image building when set as synchronized so we leave it as it is for now.
     */
    public static void setSecurity(boolean sec) {
        isSecure = sec;
        // System.out.println("Setting security family of sgx object translator");
    }

    public static boolean getSecurity() {
        return isSecure;
    }

    /**
     * Number of mirror objects in registry. This should be the same number of proxy
     * objects all things being equal.
     */
    public static int getRegistrySize() {
        return mirrorObjects.size();
    }

    public static void incNumProxies() {
        numObjs++;
    }

    /**
     * Tests if security family has been set. This is true if any proxy objects have
     * been created.
     */
    public static boolean securitySet() {
        return numObjs > 0 ? true : false;
    }

    /**
     * Retrieve object hash code and applies a supplemental hash function to the
     * result hash, which defends against poor quality hash functions. This is
     * critical because HashMap uses power-of-two length hash tables, that otherwise
     * encounter collisions for hashCodes that do not differ in lower bits. Copied
     * from WeakIdentityHashMap.java
     */
    // @CEntryPoint(name = "hash")
    public static int hash(Object k) {
        int h = System.identityHashCode(k);

        // This function ensures that hashCodes that differ only by
        // constant multiples at each bit position have a bounded
        // number of collisions (approximately 8 at default load factor).
        h ^= (h >>> 20) ^ (h >>> 12);
        return h ^ (h >>> 7) ^ (h >>> 4);
    }

}
