
package iiun.smartc;

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
import java.nio.file.Paths;

public class ResultsWriter {

    public static final String base = Paths.get("").toAbsolutePath().toString() + "/results/";

    public static void write(String line,String filePath) {
        String path = base+filePath;
        try (FileWriter fileWriter = new FileWriter(path, true)) {
            System.out.println("Registering results");
            fileWriter.write(line + "\n");

            fileWriter.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

}
