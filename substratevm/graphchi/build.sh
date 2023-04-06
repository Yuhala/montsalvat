
#
# Script to build and run graphchi-java
# Author: Peterson Yuhala
#   
#


PKG="edu.cmu.graphchi"
PKG_PATH="edu/cmu/graphchi"

# Main class
MAIN="Pagerank"

PIG="PigGraphChiBase"


BASE="$PWD/app"
LIBS="$PWD/lib/*"

CP="$LIBS:$BASE:."

BUILD_OPTS="-Xlint:unchecked -Xlint:deprecation "

JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"

DATA="$PWD/graphchi-data/fbedges"

# Build application

$JAVAC -cp $CP $BUILD_OPTS $BASE/$PKG_PATH/apps/$MAIN.java $BASE/$PKG_PATH/hadoop/$PIG.java $BASE/$PKG_PATH/vertexdata/ForeachCallback.java

# Run application

# Datasets: http://snap.stanford.edu/data/

# Page rank options:
# java -cp $CP edu.cmu.graphchi.apps.Pagerank [GRAPH-FILENAME] [NUM-OF-SHARDS] [FILETYPE]

$JAVA -cp $CP $PKG.apps.$MAIN $DATA 4 edgelist