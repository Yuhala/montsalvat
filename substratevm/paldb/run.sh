#!/bin/bash

HOME="/home/petman/projects/benchmarks-graal/paldb/paldb"
PKG_PATH="com/linkedin/paldb"
CP=$HOME

BenchMain="$CP/$PKG_PATH/BenchMain.java"

MAIN="com.linkedin.paldb.BenchMain"

LIBS="$HOME/lib/*"
OPTS="-Xlint:deprecation -Xlint:unchecked"

javac -cp $CP:$LIBS $BenchMain

java -cp $CP:$LIBS $MAIN
