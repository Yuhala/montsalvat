#!/bin/bash

HOME="/home/petman/projects/benchmarks-graal/quickcached"
PKG_PATH="com/quickserverlab/quickcached"
CP=$HOME

prepHook="$HOME/$PKG_PATH/PrepareHook.java"
cmdHandler="$HOME/$PKG_PATH/CommandHandler.java"
refMap="$HOME/$PKG_PATH/cache/impl/softreferencemap/SoftReferenceMapImpl.java"

BenchMain="$CP/$PKG_PATH/QuickCached.java"

MAIN="com.quickserverlab.quickcached.QuickCached"

LIBS="$HOME/lib/*"
OPTS="-Xlint:deprecation -Xlint:unchecked"

javac -cp $CP:$LIBS $BenchMain $prepHook $cmdHandler $refMap

java -cp $CP:$LIBS $MAIN
