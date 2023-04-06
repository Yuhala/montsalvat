
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
import java.nio.file.Paths;

public class ResultsWriter {

    public static final String results = Paths.get("").toAbsolutePath().toString() + "/results/temp.csv";

    public static void write(String line) {
        try (FileWriter fileWriter = new FileWriter(results, true)) {
            System.out.println("Writing result to temp.csv");
            fileWriter.write(line + "\n");

            fileWriter.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

}
