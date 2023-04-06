/*
 * Created on Thu Apr 15 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package edu.cmu.graphchi.apps;

import edu.cmu.graphchi.*;
import edu.cmu.graphchi.apps.DataGen;
import edu.cmu.graphchi.apps.Pagerank;
import edu.cmu.graphchi.datablocks.FloatConverter;
import edu.cmu.graphchi.engine.GraphChiEngine;
import edu.cmu.graphchi.engine.VertexInterval;
import edu.cmu.graphchi.io.CompressedIO;
import edu.cmu.graphchi.preprocessing.EdgeProcessor;
import edu.cmu.graphchi.preprocessing.FastSharder;
import edu.cmu.graphchi.preprocessing.VertexIdTranslate;
import edu.cmu.graphchi.preprocessing.VertexProcessor;
import edu.cmu.graphchi.util.IdFloat;
import edu.cmu.graphchi.util.Toplist;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.logging.LogManager;

import edu.cmu.graphchi.apps.StopWatch;

import org.graalvm.nativeimage.SecurityInfo;

@SecurityInfo(security = "untrusted")
public class BenchMain {
    private static Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);// = ChiLogger.getLogger("pagerank");
    public static final String dataDir = "/home/petman/projects/graal-tee/substratevm/graphchi/data";

    /**
     * Initialize the sharder-program.
     * 
     * @param graphName
     * @param numShards
     * @return
     * @throws IOException
     */
    protected static FastSharder createSharder(String graphName, int numShards) throws IOException {
        return new FastSharder<Float, Float>(graphName, numShards, new VertexProcessor<Float>() {
            public Float receiveVertexValue(int vertexId, String token) {
                return (token == null ? 0.0f : Float.parseFloat(token));
            }
        }, new EdgeProcessor<Float>() {
            public Float receiveEdge(int from, int to, String token) {
                return (token == null ? 0.0f : Float.parseFloat(token));
            }
        }, new FloatConverter(), new FloatConverter());
    }

    /**
     * Delete all shards created except the parent dataset file Pyuhala
     * 
     * @param parentFile
     */
    static void cleanShards(String parentFile) {
        int len = parentFile.length();
        System.out.println("-------------- Cleaning shards ---------------");
        File dir = new File(dataDir);
        File[] contents = dir.listFiles();
        // do not delete parent dataset file
        for (File f : contents) {
            if (f.isDirectory()) {
                // recursively clean other folders
                // TODO
            } else if (f.getName() == parentFile || f.getName().length() == len) {
                // do nothing: is parent file
            } else {
                f.delete();
            }

        }

    }

    /**
     * Usage: java edu.cmu.graphchi.demo.PageRank graph-name num-shards
     * filetype(edgelist|adjlist) For specifying the number of shards, 20-50 million
     * edges/shard is often a good configuration.
     */
    public static void main(String[] args) throws Exception {
        // disable logger
        LogManager.getLogManager().reset();

        // Generate social network graph
        // DataGen.genGraph(25000, 100000);

        /** Datasets */
        // Facebook
        String facebook = dataDir + "/fbedges";
        String testData = dataDir + "/gen.txt";

        // Live journal
        String ljournal = dataDir + "/soc-LiveJournal1.txt";

        String baseFilename = testData;

        // In java app name is not arg0
        int nShards = Integer.parseInt(args[0]);
        String fileType = "edgelist";// (args.length >= 3 ? args[2] : null);

        CompressedIO.disableCompression();

        // Calculate time to process shards and calculate page rank
        StopWatch clock = new StopWatch();
        clock.start();

        /* Create shards */
        FastSharder sharder = createSharder(baseFilename, nShards);
        if (baseFilename.equals("pipein")) { // Allow piping graph in
            sharder.shard(System.in, fileType);
        } else {
            if (!new File(ChiFilenames.getFilenameIntervals(baseFilename, nShards)).exists()) {
                sharder.shard(new FileInputStream(new File(baseFilename)), fileType);
            } else {
                logger.info("Found shards -- no need to preprocess");
            }
        }

        double shardTime = clock.stop();
        System.out.println("################# Sharding time: " + shardTime + "###################");

        /* Run GraphChi */
        // GraphChiEngine<Float, Float> engine = new GraphChiEngine<Float,
        // Float>(nShards, baseFilename);

        clock.start();
        GraphChiEngine engine = new GraphChiEngine(nShards, baseFilename);
        // engine.setEdataConverter(new FloatConverter());
        // engine.setVertexDataConverter(new FloatConverter());

        // pyuhala: avoids serialization issues with FloatConverter objects
        engine.setEdataConverterFloat();
        engine.setVDataConverterFloat();

        engine.setModifiesInedges(false); // Important optimization

        // Pagerank program = new Pagerank();
        String program = "Pagerank";

        engine.run(program, 4);

        double engineTime = clock.stop();
        double totalTime = shardTime + engineTime;

        System.out.println("################ Runtime (engine): " + engineTime + "##################");
        String benchResult = nShards + "," + engineTime + "," + shardTime + "," + totalTime;
        System.out.println("Benchresult: " + benchResult);
        ResultsWriter.write(benchResult);

        /* Output results */
        System.out.println("-------- Number of vertices ---------------: " + engine.numVertices());
        engine.printTop(10);

        /** Clean shards */
        // cleanShards(baseFilename);

    }
}
