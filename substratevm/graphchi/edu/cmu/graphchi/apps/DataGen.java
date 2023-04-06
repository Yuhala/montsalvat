
/*
 * Created on Fri Apr 16 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

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
import java.util.Random;

public class DataGen {

    public static final String data = "/home/petman/projects/graal-tee/substratevm/graphchi/data/gen.txt";

    static void write(String line) {
        try (FileWriter fileWriter = new FileWriter(data, true)) {

            fileWriter.write(line + "\n");

            fileWriter.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Generates a graph with the given parameters
     * 
     * @param numVertices
     * @param numEdges
     */
    public static void genGraph(int numVertices, int numEdges) {

        /**
         * Generate random vertices/edges. Set the corresponding bit in the adjacency
         * matrix to 1 once an edge is created. This prevents repeated edges.
         */
        int[][] adjMatrix = new int[numVertices][numVertices];

        Random rand = new Random();

        int v1 = 0;
        int v2 = 0;
        for (int i = 0; i < numEdges; i++) {

            // both vertices should not be the same and the edge should not exist
            while ((v1 == v2) || adjMatrix[v1][v2] == 1) {
                v1 = rand.nextInt(numVertices);
                v2 = rand.nextInt(numVertices);
            }

            adjMatrix[v1][v2] = 1;

            /** Write generated edge to file */
            String edge = Integer.toString(v1) + " " + Integer.toString(v2);
            write(edge);

        }
    }

}
