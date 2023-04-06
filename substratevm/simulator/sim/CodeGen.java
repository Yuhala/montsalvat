/*
 * Created on Sat Apr 10 2021
 * Generates class files for a partition simulation program
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package sim;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.io.BufferedReader;
import java.io.File;

import java.io.FileNotFoundException;
import java.nio.file.DirectoryIteratorException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.lang.Math;

import java.nio.file.Paths;

public class CodeGen {

    /** Total number of classes to generate */
    public static final int NUM_CLASSES = 100;
    /** Template path */
    public static final String templateBase = Paths.get("").toAbsolutePath().toString() + "/simulator/templates";
    /** Code base */
    public static final String codeBase = Paths.get("").toAbsolutePath().toString() + "/simulator/sim";
    /** Constants used by code writer */
    public static final String space = " ";
    /**
     * Method name prefixes and parameters. All classes will have these methods but
     * for the last digit which will ensure uniqueness.
     */
    public static final List<String> methods = Arrays.asList("createProxy", "writeSequence", "saySomething", "doFFT");

    /**
     * Specifies if the full program will be run in the enclave i.e no partitioning
     */
    public static boolean full = false;

    /**
     * Generates main class of simulation program
     * 
     * @param numTrusted
     */
    static void generateMainClass(int numTrusted) {

        int numUntrusted = NUM_CLASSES - numTrusted;
        String mainClassName = codeBase + "/SimMain.java";
        String header = readTemplate(templateBase + "/header.txt");

        String code = "";
        // write header
        code += header;
        // write main class
        code += "public class SimMain{";
        // write main method
        code += " public static void main(String[] args) {";

        code += "Untrusted0 uObj = new Untrusted0(\"untrusted\",-1);";
        code += "Trusted0 tObj = new Trusted0(\"trusted\",-1);";
        //code += "tObj.doSomething_trusted0(2);";
        //code += "uObj.doSomething_Intrusted0(2);";
        // add timer start
        code += "StopWatch clock = new StopWatch();";
        code += "clock.start();";

        //obj.doSomething_trusted0(i);
        /** Instantiate trusted objects and call their methods */
        for (int i = 0; i < numTrusted; i++) {
            code += "Trusted" + i + space + "secObj" + i + " = new Trusted" + i + "(\"trusted\",0);";
            //code += "secObj" + i + ".createProxy_" + "Secure" + i + "();";
            code += "secObj" + i + ".writeSequence_" + "Truste" + i + "();";
            // code += "secObj" + i + ".saySomething_" + "Secure" + i + "(\"Hi I'm a secure
            // object.\");";
            code += "secObj" + i + ".doFFT_" + "Trusted" + i + "();";
            // double[] array = SimFFT.makeRandom(n);
        }

        //--------------------------------- Create n proxies: out--> in ----------------------
        //code += "int numProxies = Integer.parseInt(args[0]);";
        //code += "for (int i = 0;i < numProxies;i++){";
        //code += "Intrusted0 uObj = new InSecure0(i);";
        //code += "}";
       

        //---------------------------------- Create n proxies: in-->out  ---------------------
        //code += "int numProxies = Integer.parseInt(args[0]);";
        //code += "InSecure0.createProxy_InSecure0(numProxies);";
        

        /** Instantiate insecure objects and call their methods */
        for (int i = 0; i < numUntrusted; i++) {
            code += "Untrusted" + i + space + "inSecObj" + i + " = new Untrusted" + i + "(\"untrusted\",0);";
            //code += "inSecObj" + i + ".createProxy_" + "Intrusted" + i + "();";
            //code += "inSecObj" + i + ".writeSequence_" + "InSecure" + i + "();";
            code += "inSecObj" + i + ".doSomething_" + "Untrusted" + i + "(\"petman\");";
            // System.out.println("Num of bytes in 123: "+test.getBytes().length);
            // code += "inSecObj" + i + ".saySomething_" + "InSecure" + i + "(\"Hi I'm an
            // insecure object.\");";
            code += "inSecObj" + i + ".doFFT_" + "Untrusted" + i + "();";
        }

        // add timer stop
        code += "double total = clock.stop();";
        code += "System.out.println(\">>>>>>>>>>>>>>> Total time is: \"+total);";
        code += "ResultsWriter.write(Double.toString(total));";

        // close braces

        // code += "SimFFT.doFFT(1024*32);";
        code += "} }";
        writeFile(mainClassName, code);

    }

    /**
     * Generates simulation classes
     * 
     * @param numTrusted
     */
    static void generateClasses(int numTrusted) {

        int numUntrusted = NUM_CLASSES - numTrusted;

        String header = readTemplate(templateBase + "/header.txt");

        // Add graal headers for partitioned version
        String graal = readTemplate(templateBase + "/graalHeaders.txt");

        header += graal;

        /** Generate trusted classes */
        for (int i = 0; i < numTrusted; i++) {
            String annotations = full ? "" : "@SecurityInfo(security = \"trusted\")";

            String className = codeBase + "/trusted" + i + ".java";
            String code = "";
            // add header
            code += header;
            // add class annotation
            code += annotations;
            // write class name
            code += "public class Trusted" + i + space + "{";
            code += "String name;";
            code += "int id;";
            // write constructor
            code += "public Trusted" + i + "(String str, int n){this.name = str;this.id = n;}";
            // write methods
            code += getClassMethods("Trusted", i);
            // close braces
            code += "}";
            // generate file
            writeFile(className, code);

        }

        /** Generate intrusted classes */
        for (int i = 0; i < numUntrusted; i++) {
            String annotations = full ? "" : "@SecurityInfo(security = \"untrusted\")";
            String className = codeBase + "/InTrusted" + i + ".java";
            String code = "";
            // add header
            code += header;
            // add class annotation
            code += annotations;
            // write class name
            code += "public class Untrusted" + i + space + "{";
            code += "String name;";
            code += "int id;";
            // write constructor
            code += "public Untrusted" + i + "(String str, int n){this.name = str;this.id = n;}";
            // write methods
            code += getClassMethods("Untrusted", i);
            // close braces
            code += "}";
            // generate file
            writeFile(className, code);
        }

    }

    /**
     * Reads content of template file
     * 
     * @param file
     * @return
     */
    static String readTemplate(String file) {
        String code = "";
        try (BufferedReader fileReader = new BufferedReader(new FileReader(file))) {

            String line;
            while ((line = fileReader.readLine()) != null) {
                code += line;
            }
            fileReader.close();

        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        return code;
    }

    /**
     * Gets code for all class methods
     * 
     * @param index
     * @param suffix
     * @return
     */
    static String getClassMethods(String suffix, int index) {
        /**
         * NB: the templates contain only the body of the methods. You could add a
         * comment at the top of each template to specify the signature just in case
         */
        // TODO: do this in a loop with methods and params in a hashmap
        String code = "";
        // write method 1
        code += "public static void createProxy_" + suffix + index + "(int numProxies){";
        code += readTemplate(templateBase + "/createProxy.txt");
        code += "}";
        // write method 2
        code += "public void writeSequence_" + suffix + index + "(){";
        code += readTemplate(templateBase + "/writeSequence.txt");
        code += "}";

        // write method 3
        code += "public void doSomething_" + suffix + index + "(String str){";
        code += readTemplate(templateBase + "/doSomething.txt");
        code += "}";

        // method 4 (FFT)
        code += "public void doFFT_" + suffix + index + "(){";
        code += readTemplate(templateBase + "/doFFT.txt");
        code += "}";

        // return
        return code;
    }

    /**
     * Writes code to file
     * 
     * @param file
     * @param code
     */
    static void writeFile(String file, String code) {

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(code);
            fileWriter.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }

    /** Deletes all generated class files */
    static void cleanup() {
        File dir = new File(codeBase);
        File[] contents = dir.listFiles();
        // do not delete folders or code generator
        for (File f : contents) {
            if (!f.isDirectory() && isGen(f.getName())) {
                f.delete();
            }

        }

    }

    /**
     * Checks if the file is generated or not. This should be done carefully because
     * the result of this test will decide if the class is deleted or not. It
     * returns true if the file with give name is generated, and false if not.
     * 
     * @param name
     * @return
     */
    static boolean isGen(String name) {
        boolean isGen = true;
        boolean test = name.contains("CodeGen") || name.contains("SimFFT") || name.contains("StopWatch")
                || name.contains("ResultsWriter");
        if (test) {
            isGen = false;
        }

        return isGen;

    }

    /**
     * Custom logger
     * 
     * @param n
     */
    static void log(int n) {
        System.out.println("Generating: " + n + " trusted classes and : " + (NUM_CLASSES - n) + " intrusted classes");
    }

    /**
     * Generates n trusted classes and NUM_CLASSES - n intrusted classes. An object
     * will be instantiated for each class and the different instance methods
     * called. By varying the number of trusted classes in the enclave, we can study
     * the performance variations.
     * 
     * @param args
     */
    public static void main(String[] args) {
        /**
         * Parameters: full part 25
         */

        double percent = 100.0;
        int p = 100;
     
        percent = Double.parseDouble(args[0]);

        p = Integer.parseInt(args[0]);
        System.out.println("P is : " + p);

        double temp = (percent / 100.0) * NUM_CLASSES;
        int numTrusted = (int) Math.floor(temp);

        System.out.println("Temp is : " + temp);

        //cleanup();

        System.out.println("Number of sec classes: "+numTrusted);
        //System.exit(0);
        log(numTrusted);
        generateClasses(numTrusted);
        generateMainClass(numTrusted);
    }

}
