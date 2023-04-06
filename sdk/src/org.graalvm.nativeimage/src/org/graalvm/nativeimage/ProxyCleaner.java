/*
 * Created on Mon Feb 01 2021
 *
 * Copyright (c) 2021 Gael Thomas, Peterson Yuhala, IIUN
 */

package org.graalvm.nativeimage;

import java.util.HashMap;

import org.graalvm.nativeimage.CurrentIsolate;
import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.function.CFunction.Transition;
import org.graalvm.nativeimage.SecurityInfo;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

public class ProxyCleaner implements Runnable {
    public static long WAIT = 100;//default
    public static final long SLEEP = 2000;
    private static boolean stopped = false;
    private boolean isSecure = true;
    /** Weak references of proxy objects */
    private static List<WeakReference<Object>> refs = new ArrayList<WeakReference<Object>>();
    /** Hash values of proxy objects */
    private static List<Integer> ids = new ArrayList<Integer>();

    /**
     * Stores hashes of proxy objects with the associated index in the list. This
     * enables us to rapidly obtain a weak ref using the proxy's hash
     */
    private static HashMap<Integer, Integer> proxyIds = new HashMap<>(10_000);

    public ProxyCleaner(boolean security,long sleepTime) {
        this.isSecure = security;
        WAIT = sleepTime;
        (new Thread(this)).start();
    }

    /** Removes corresponding mirror object in opposite runtime. */
    public void cleanup(int id) {

        // System.out.println("cleanup: " + id);

    }

    public void run() {
        if (this.isSecure) {
            // wait(5 * WAIT);
            this.doCleanupIn();
            // synchronized (this) {
            // ecall_doProxyCleanupIn(CurrentIsolate.getCurrentThread());
            // }

        } else {
            this.doCleanupOut();
        }

    }

    /**
     * Each thread will lock the class but its not a problem: we have one thread
     * each for proxy cleanup in and out. This method will be called by different
     * proxy classes in the application.
     */
    public static void add(Object o, int id) {
        refs.add(new WeakReference<Object>(o));
        ids.add(id);
        // add the proxy hash and its index in the list
        proxyIds.put(id, ids.size() - 1);
        // System.out.println("Add proxy object weak ref to registry");
    }

    @CFunction(value = "ecall_doProxyCleanupIn", transition = CFunction.Transition.TO_NATIVE)
    public static native void ecall_doProxyCleanupIn(IsolateThread iso);

    @CFunction(value = "ecall_mirrorCleanupIn", transition = CFunction.Transition.TO_NATIVE)
    public static native void ecall_mirrorCleanupIn(IsolateThread iso, int hash);

    @CFunction(value = "ocall_mirrorCleanupOut", transition = CFunction.Transition.TO_NATIVE)
    public static native void ocall_mirrorCleanupOut(IsolateThread iso, int hash);

    /**
     * Mirror cleanups are done when the corresponding proxy object is garbage
     * collected.
     */
    @CEntryPoint(name = "mirrorCleanupIn")
    @SecurityInfo(transition = "ecall")
    static void mirrorCleanupIn(IsolateThread t, int proxyHash) {

        SGXObjectTranslator.removeMirrorObject(proxyHash);
        // System.out.println("Removed mirror object from registry in");

    }

    @CEntryPoint(name = "mirrorCleanupOut")
    @SecurityInfo(transition = "ocall")
    static void mirrorCleanupOut(IsolateThread t, int proxyHash) {

        SGXObjectTranslator.removeMirrorObject(proxyHash);
        // System.out.println("Removed mirror object from registry out");

    }

    @CEntryPoint(name = "doProxyCleanupIn")
    @SecurityInfo(transition = "ecall")
    static void doProxyCleanupIn(IsolateThread t) {
        /**
         * The associated proxy cleaner object/thread for enclave cleanup is launched in
         * the untrusted runtime.
         */

        while (true) { // ; // each second
            // wait(WAIT);
            for (int i = 0; i < 3; i++) {
                System.out.println("Doing proxy cleanup in");
            }
        }

    }

    /**
     * Creates two threads: one does proxy cleanup outside, the other does
     * transitions into the enclave runtime and does proxy cleanup there.
     */
    public static void initProxyCleaners(long sleepTime) {

        // set security family
        SGXObjectTranslator.setSecurity(false);
        System.out.println("=================== Initializing proxy cleaners ======================");
        ProxyCleaner cleanerOut = new ProxyCleaner(false,sleepTime);
        ProxyCleaner cleanerIn = new ProxyCleaner(true,sleepTime);

        // ecall_initProxyCleanupIn(CurrentIsolate.getCurrentThread());

        // Thread.sleep(2000);

    }

    /** Stop proxy cleaners */
    public static void stopProxyCleaners() {
        System.out.println("=================== Stopping proxy cleaners ======================");
        stopped = true;
    }

    private void doCleanupIn() {
        try {
            synchronized (this) {
                wait(WAIT); // each second
                // ecall_doProxyCleanupIn(CurrentIsolate.getCurrentThread());
            }

        } catch (Exception e) {
            e.getStackTrace();
        }
    }

    private void doCleanupOut() {
        // set security family
        // SGXObjectTranslator.setSecurity(false);
        try {
            // System.out.println("hello, thread");
            synchronized (this) {
                while (!stopped) {
                    wait(WAIT); // each second

                    for (int i = 0; i < refs.size();) {
                        /** get the strong ref from weak ref and test if it's null */
                        if (refs.get(i).get() == null) {
                            cleanup(ids.get(i));
                            proxyIds.remove(ids.get(i));
                            ecall_mirrorCleanupIn(CurrentIsolate.getCurrentThread(), ids.get(i));
                            // compact
                            int n = refs.size() - 1;
                            refs.set(i, refs.get(n));
                            refs.remove(n);
                            ids.set(i, ids.get(n));
                            ids.remove(n);
                        } else
                            i++;
                    }
                }
            }
        } catch (Exception e) {
            e.getStackTrace();
        }
    }

    /**
     * This method returns a strong reference to the proxy object with the given
     * hash id.
     * 
     * @param hashId
     */
    public static Object getProxy(int hashId) {

        int index = proxyIds.get(hashId);
        Object obj = refs.get(index).get();

        if (obj == null) {
            System.out.println("Getting a null proxy object");
        }
        return obj;

    }

    /*
     * public static void main(String[] args) throws InterruptedException {
     * 
     * 
     * for (int i = 0; i < 100; i++) cleaner.add(new Object(), i);
     * 
     * System.gc(); Thread.sleep(2000);
     * 
     * cleaner.stopped = true; }
     */
}