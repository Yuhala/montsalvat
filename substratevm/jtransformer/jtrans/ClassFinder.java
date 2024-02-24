
/*
 * Created on Thu Jan 14 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package jtrans;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;
import java.lang.*;

import org.graalvm.nativeimage.SecurityInfo;

public class ClassFinder {
    private List<String> appClasses = new ArrayList<String>();
    private List<String> untrustedClasses;
    private List<String> trustedClasses;
    private ClassLoader loader;

    // class files will be searched here
    public static String home;

    // empty string
    public static final String emptyString = "";

    public ClassFinder(String path, String pkg, ClassLoader cLoader) {
        // the same files are copied in trusted and untrusted folders
        home = path + "/trusted";
        try {
            // this.appClasses = getClassNames(pkg, cLoader);
            getClassNames(emptyString, home, appClasses);
        } catch (Exception e) {
            e.getStackTrace();
        }

        this.loader = cLoader;
        this.untrustedClasses = new ArrayList<String>();
        this.trustedClasses = new ArrayList<String>();
        this.runSecurityFilter();
    }

    /**
     * Searches package folders to obtain class names Author: pyuhala
     * 
     * @param pkg
     * @return
     */
    public static void getClassNames(String pkg, String dirPath, List<String> classes) throws IOException {
        File dir = new File(dirPath);
        File[] fList = dir.listFiles();
        if (fList != null) {
            for (File file : fList) {
                // add only .class files
                if (file.isFile() && file.getName().endsWith(".class")) {
                    String name = (pkg.equals("")) ? file.getName() : pkg + "." + file.getName();
                    name = removeExtension(name);
                    // System.out.println("ClassName: " + name);
                    // classes.add(pkg + "." + removeExtension(file.getName()));
                    classes.add(name);
                } else if (file.isDirectory()) {
                    String name = (pkg.equals("")) ? file.getName() : pkg + "." + file.getName();
                    getClassNames(name, file.getAbsolutePath(), classes);
                }
            }
        }

    }

    // to fix
    public static List<String> getClassNames(String pkg, ClassLoader cLoader)
            throws ClassNotFoundException, IOException {

        assert cLoader != null : "class loader is null";
        String path = pkg.replace('.', '/');
        Enumeration<URL> resources = cLoader.getResources(path);

        List<File> dirs = new ArrayList<File>();
        int i = 0;

        while (resources.hasMoreElements()) {
            URL resource = resources.nextElement();
            dirs.add(new File(resource.getFile()));
            System.out.println("Resource: " + dirs.get(i).getName());
            i++;
        }
        /** List of class names */
        List<String> classes = new ArrayList<String>();
        for (File directory : dirs) {
            classes.addAll(findClasses(directory, pkg));
        }

        return classes;
    }

    public static List<String> findClasses(File directory, String pkg) throws ClassNotFoundException {
        System.out.println("findClasses: " + pkg);
        List<String> classNames = new ArrayList<String>();
        if (!directory.exists()) {
            return classNames;
        }
        String temp = pkg;
        File[] files = directory.listFiles();
        for (File file : files) {
            if (file.isDirectory()) {
                assert !file.getName().contains(".") : "folder names contains .";
                classNames.addAll((findClasses(directory, pkg + "." + file.getName())));
            } else if (file.getName().endsWith(".class")) {
                classNames.add(pkg + "." + removeExtension(file.getName()));
                System.out.println("Found class: " + file.getName());

            }
        }
        return classNames;
    }

    public List<String> getTrustedClasses() {
        return this.trustedClasses;
    }

    public List<String> getUntrustedClasses() {
        return this.untrustedClasses;
    }

    /** Classify classes as trusted or not */
    public void runSecurityFilter() {

        for (String cname : this.appClasses) {
            //System.out.println("runSecurityFilter: " + cname);
            /**
             * This is just a hack for graphchi: maybe test only for the names of annotated classes. The
             * tested class is not found by the class loader but we did not annotate either so
             * not useful to us here.
             */
            if (cname.contains("PigGraphChiBase")) {
                continue;
            }
            try {
                Class<?> clazz = Class.forName(cname, false, this.loader);
                SecurityInfo info = (SecurityInfo) clazz.getAnnotation(SecurityInfo.class);
                if (info == null) {
                    // neutral class: will not be modified
                    continue;
                }
                if (isTrustedClass(info)) {
                    this.trustedClasses.add(cname);
                } else {
                    this.untrustedClasses.add(cname);
                }

            } catch (ClassNotFoundException e) {
                e.getStackTrace();
            }
        }
    }

    /**
     * Determines if a class is trusted or not.
     * 
     * @param info
     * @return
     */
    public boolean isTrustedClass(SecurityInfo info) {
        if (info.security().equals("trusted")) {
            return true;
        } else if (info.security().equals("untrusted")) {
            return false;
        } else {
            System.out.println("Wrong security annotation on class");
            return false;// TODO: abort here or consider class untrusted ??
        }

    }

    public static String removeExtension(String fileName) {
        final int lastPointPos = fileName.lastIndexOf('.');
        if (lastPointPos <= 0) {
            return fileName;
        } else {
            return fileName.substring(0, lastPointPos);
        }
    }
}
