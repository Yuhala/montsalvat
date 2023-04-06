package edu.cmu.graphchi.apps;

import edu.cmu.graphchi.*;
import edu.cmu.graphchi.util.IdFloat;
import edu.cmu.graphchi.util.Toplist;
import edu.cmu.graphchi.engine.VertexInterval;

import java.util.TreeSet;
//import java.util.logging.Logger;
//import java.util.logging.LogManager;

/**
 * Example application: PageRank (http://en.wikipedia.org/wiki/Pagerank)
 * Iteratively computes a pagerank for each vertex by averaging the pageranks of
 * in-neighbors pageranks.
 * 
 * @author akyrola
 */
import org.graalvm.nativeimage.SecurityInfo;


@SecurityInfo(security = "trusted")
public class Pagerank implements GraphChiProgram<Float, Float> {

    public void update(ChiVertex<Float, Float> vertex, GraphChiContext context) {
        if (context.getIteration() == 0) {
            /* Initialize on first iteration */
            vertex.setValue(1.0f);
        } else {
            /*
             * On other iterations, set my value to be the weighted average of my in-coming
             * neighbors pageranks.
             */
            float sum = 0.f;
            for (int i = 0; i < vertex.numInEdges(); i++) {
                sum += vertex.inEdge(i).getValue();
            }
            vertex.setValue(0.15f + 0.85f * sum);
        }

        /*
         * Write my value (divided by my out-degree) to my out-edges so neighbors can
         * read it.
         */
        float outValue = vertex.getValue() / vertex.numOutEdges();
        for (int i = 0; i < vertex.numOutEdges(); i++) {
            vertex.outEdge(i).setValue(outValue);
        }

    }

    /**
     * Callbacks (not needed for Pagerank)
     */
    public void beginIteration(GraphChiContext ctx) {
    }

    public void endIteration(GraphChiContext ctx) {
    }

    public void beginInterval(GraphChiContext ctx, VertexInterval interval) {
    }

    public void endInterval(GraphChiContext ctx, VertexInterval interval) {
    }

    public void beginSubInterval(GraphChiContext ctx, VertexInterval interval) {
    }

    public void endSubInterval(GraphChiContext ctx, VertexInterval interval) {
    }

}
