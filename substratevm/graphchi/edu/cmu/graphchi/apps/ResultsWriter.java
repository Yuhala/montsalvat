

package edu.cmu.graphchi.apps;

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

public class ResultsWriter {

    public static final String results = "/home/petman/projects/graal-tee/sgx/results/temp.csv";

    public static void write(String line) {
        try (FileWriter fileWriter = new FileWriter(results, true)) {

            fileWriter.write(line + "\n");

            fileWriter.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

}
