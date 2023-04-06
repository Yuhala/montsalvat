/*
 * Created on Fri Feb 19 2021
 *  
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package jtrans;

import java.io.FileReader;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.Reader;
import java.io.FileWriter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.nio.file.Paths;

/**
 * We use methods here to add serializable types to json config files generated
 * by the native image agent. We register the associated types duringjavassist
 * bytecode instrumentation in JAssistTransformer.
 */
public class AgentHelper {

    // TODO: do not hardcode this here
    /** Path to serialization configuration file. */
    public static final String fileName = Paths.get("").toAbsolutePath().toString()// returns substratevm dir if you run
                                                                                   // app script from there
            + "/META-INF/native-image/serialization-config.json";
    /**
     * These classes are needed by the serializer but for some reason are not picked
     * up. So I add them manually.
     * 
     */

    public static final List<String> classes = Arrays.asList("java.lang.Number", "java.lang.Object",
            "java.lang.Integer", "java.lang.Double");

    /**
     * Json simple lib does not support HashMap generics. The following suppresses
     * any warnings thereof
     */
    @SuppressWarnings("unchecked")
    public static void addClasses(List<String> classList) {

        // System.out.println("config path: " + fileName);
        // new JSONObject(new HashMap<String, String>().put(K, V))

        JSONArray array = new JSONArray();
        JSONObject jsonObj;

        // JSON parser object to parse read file
        JSONParser jsonParser = new JSONParser();

        try (FileReader reader = new FileReader(fileName)) {
            // Read JSON file
            Object obj = jsonParser.parse(reader);

            array = (JSONArray) obj;
            // System.out.println(array);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        /** Add classes captured by jtransformer to serialization config */
        for (String className : classList) {
            /** Create new: {"name":"pkg.classname"} json object */
            jsonObj = new JSONObject();
            jsonObj.put("name", className);
            // System.out.println("Writing class to serializer: " + className);
            /** Add object to array */
            array.add(jsonObj);
        }

        /** Add extra classes that may not be picked up */
        for (String name : classes) {
            jsonObj = new JSONObject();
            jsonObj.put("name", name);
            array.add(jsonObj);
        }

        try {
            FileWriter file = new FileWriter(fileName, false);

            file.write(array.toJSONString());
            file.flush();
            file.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
