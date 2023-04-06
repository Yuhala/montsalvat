#!/bin/bash
#
# Copyright (c) 2020 Peterson Yuhala, IIUN
#

#
# You must be in the graal-tee directory as root here: ie make sure PWD = graal-tee dir
# To run your app, copy the top most package folder to the SVM directory and modify the app related
# varialbles accordingly
#
#

#change directory to present dir
cd "$(dirname "$0")"

#read secure class percentage (arg 1)
SEC_PERCENT=$1

#name of app folder in SVM directory
APP_NAME="simulator"

#package path (same at the top of main class)
APP_PKG="sim"

#full package path (above with . replaced with /)
PKG_PATH="sim"

#pkg prefix is the first part (/subfolder) of the package name
PKG_PREFIX="sim"

SVM_DIR="$PWD/substratevm"
SGX_DIR="$PWD/sgx"
#GRAAL_HOME="$PWD/graalvm-ce-java11-21.0.0"  # pre-built: for native image agent
#GRAAL_HOME="$PWD/sdk/latest_graalvm_home" # only useful after graal build

#JAVA_HOME="$PWD/openjdk1.8.0_282-jvmci-21.1-b01"

#export JAVA_HOME=$JAVA_HOME

#
# NB: the jdk above does not come with the native image agent.
# We downloaded a prebuilt version of graalvm-ce-java11-21.0.0 and copied
# the agent.so file to the below directory
#
AGENT_PATH="$JAVA_HOME/jre/lib/amd64/libnative-image-agent.so"

APP_DIR="$SVM_DIR/$APP_NAME"
JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"

# SGX proxies generated by graal SGX proxy generator
EDL_FILES=("/tmp/graalsgx_ecalls.edl" "/tmp/graalsgx_ocalls.edl")
TRUSTED_PROXIES=("/tmp/graalsgx_ecalls.hpp" "/tmp/graalsgx_ocalls_proxy.hpp")
UNTRUSTED_PROXIES=("/tmp/graalsgx_ocalls.hpp" "/tmp/graalsgx_ecalls_proxy.hpp")

# Ignore jvmci version check
# "warn"

#TODO put annotations in a com.oracle.svm.graalsgx package
# Give this file x permission if it does not have. Its present perm will probably be: rw-rw-r-- (664). Change to 764
# chmod 764 /path/to/graal-sdk.jar

#to find the relevant files: find . -name "filename"
GRAAL_LIBS="$PWD/sdk/latest_graalvm_home/lib/graal/*"
GRAALVM_LIBS="$PWD/sdk/latest_graalvm_home/lib/graalvm/*"

SVM_LIBS="$PWD/sdk/latest_graalvm_home/lib/svm/builder/svm.jar"
GRAAL_SDK="$PWD/sdk/mxbuild/dists/jdk1.8/graal-sdk.jar"

#
# Graal sdk bin causes problems! do not add to the cp never add anywhere!!
# I kept it here just FYI
#

#GRAAL_SDK_BIN="$PWD/sdk/mxbuild/src/org.graalvm.nativeimage/bin"
JTRANSFORMER="$SVM_DIR/jtransformer"
JTRANS="$JTRANSFORMER/jtrans"
JAVA_ASSIST="$JTRANSFORMER/javassist-3.26.0-GA.jar"
APP_LIBS="$APP_DIR/lib/*"

LIBS="$JTRANSFORMER/json-simple-1.1.jar"

SIM_MAIN="SimMain"

GEN="CodeGen"

OTHERS=""
DB="$APP_DIR/data"

#
# class path variable
# do not add secure and unsecure jtransformer dirs to the cp else jtransformer or native img builder may see
# multiple versions of the classes. This could lead to problems.
#

JTRANS_CP="$GRAAL_SDK:$JTRANSFORMER:$JAVA_ASSIST:$LIBS"

CP="$JTRANS_CP:$SVM_DIR:$APP_DIR:$APP_LIBS"


# function to clean generated data files
function clean_gen () {
    echo "-------------------- Cleaning generated classes --------------------------"
    find $SVM_DIR/simulator/sim -type f -name "*Secure*" -delete
    rm $SVM_DIR/simulator/write.txt
}

#clean old/stale files and objects and rebuild svm if changed
OLD_OBJS=("/tmp/*.edl" "/tmp/main_in.o" "/tmp/main_out.o" "$APP_DIR/*.class" "$SGX_DIR/Enclave/graalsgx/*.o" "$SGX_DIR/App/graalsgx/*.o" "$APP_DIR/$APP_NAME.jar")
cd $SVM_DIR
echo "--------------- Cleaning old files and objects ---------------"
for obj in "${OLD_OBJS[@]}"; do
    rm -fv $obj
done

# clean proxy files
#rm -fv $SGX_DIR/Enclave/graalsgx/edl/*
#rm -fv $SGX_DIR/Enclave/graalsgx/proxy/*
#rm -fv $SGX_DIR/App/graalsgx/proxy/*

# Adding java assist library as class path suffix
#mx --cp-sfx $JAVA_ASSIST build

# in case you encounter strange problems with mx native-image or SecurityInfo annotation absent, uncomment below cmds and rebuild

function build_graal {
    rm -r svmbuild
    mx clean
    mx build
}

#build_graal
#exit 1


function restore_app {
    rm -rf $APP_NAME
    cp -rf ./tmp/$APP_NAME $SVM_DIR
    rm -rf ./tmp/*
}

# restore app from tmp folder if present
cp -rf ./tmp/$APP_NAME $SVM_DIR
rm -rf ./tmp/*

#exit 1
#clean app classes
echo "--------------- Cleaning $APP_NAME classes -----------"
find $APP_DIR -name "*.class" -type f -delete

#clean old generated files
clean_gen

#app build options
BUILD_OPTS="-Xlint:unchecked -Xlint:deprecation"


echo "--------------- Building code generator -----------------"
$JAVAC -cp $CP $BUILD_OPTS $APP_DIR/$PKG_PATH/$GEN.java $OTHERS


echo "---------------- Running code generator -----------------"
$JAVA_HOME/bin/java -cp $CP $APP_PKG.$GEN $SEC_PERCENT


echo "--------------- Compiling simulator---------------"
$JAVAC -cp $CP $BUILD_OPTS $APP_DIR/$PKG_PATH/$SIM_MAIN.java $OTHERS


#--------------------------------------------------------------------------------


#clean any old files
rm $SVM_DIR/simulator/write.txt

#run unchanged application in jvm to generate any useful configuration files: reflection, serialization, dynamic class loading etc
echo "--------------- Running $APP_NAME on JVM to generate useful config files-----------"
mkdir -p META-INF/native-image
$JAVA_HOME/bin/java -agentlib:native-image-agent=config-output-dir=META-INF/native-image -cp $CP $APP_PKG.$SIM_MAIN 1000


#exit 1
#--------------------------------------------------------------------------------

#
# copy freshly compiled class files/app package/jar to java assist transformer module
# classes in the secure folder will be instrumented for the secure image build
# classes in the unsecure folder will be instrumented for the unsecure image build
# unannotated classes in both secure and unsecure dirs will be unchanged
#

#
# in the event of permission problems, change ownership of the project folder
# sudo chown -R ${USER} graal-tee/
#

#-------------------------------------------------------------------------------
# Clean secure and unsecure folders
rm -rf $JTRANSFORMER/secure/*
rm -rf $JTRANSFORMER/unsecure/*

#-------------------------------------------------------------------------------
echo "--------------- Copy class files to javassist transformer ---------------"

cp -rf $APP_DIR/$PKG_PREFIX $JTRANSFORMER/secure
cp -rf $APP_DIR/$PKG_PREFIX $JTRANSFORMER/unsecure

# the source files are probably not needed
# NB: maybe this is not needed
#find $JTRANSFORMER/secure -type f -name '*.java' -delete
#find $JTRANSFORMER/unsecure -type f -name '*.java' -delete
#-------------------------------------------------------------------------------

# temp directory to hold app folder just in case we accidentally delete them
# after all the movements :-)
mkdir -p tmp
mv $APP_DIR ./tmp

# build java assist class transformer
$JAVA_HOME/bin/javac -cp $CP -Xlint:unchecked $JTRANS/JAssistClassTransformer.java

#exit 1
#
# run java assist class transformer
# the arg0: jtransformer parent dir arg1: app pkg name
#

#|------------------------------------Instrumentation---------------------------------
#|
echo "--------------- Instrumenting classes in jassist transformer ---------------"
$JAVA_HOME/bin/java -cp $JTRANS_CP:$JTRANS jtrans.JAssistClassTransformer $JTRANSFORMER $PKG_PREFIX
#|
#|------------------------------------Instrumentation---------------------------------

# native image build options
SVM_OPTS="--allow-incomplete-classpath -H:+UseOnlyWritableBootImageHeap"
GC_OPTS="-R:PercentTimeInIncrementalCollection=10"
NATIVE_IMG_OPTS="--shared --allow-incomplete-classpath --no-fallback"
ISO_OPTS="-H:-SpawnIsolates"
ERROR_OPTS="-H:+ReportExceptionStackTraces"

# replace app folder with secure-transforms
echo "--------------- Moving transformed classes for secure image gen ---------------"
#rm -rf $APP_DIR
mkdir -p $APP_NAME
cp -R $JTRANSFORMER/secure/* $APP_DIR

#$JAVA_HOME/bin/native-image $APP_PKG.Main
#TODO: build image directly from secure/unsecure folders without copying
#exit 1
# build secure image
mx native-image -cp $CP $NATIVE_IMG_OPTS $ERROR_OPTS --sgx-in $APP_PKG.$SIM_MAIN
#rm Main.class

restore_app
exit 1
# mv unsecure-transforms to app folder for unsecure image
echo "--------------- Moving transformed classes for unsecure image gen ---------------"
#rm -rf $APP_DIR
cp -R $JTRANSFORMER/unsecure/* $APP_DIR

#build unsecure image
mx native-image -cp $CP $NATIVE_IMG_OPTS --sgx-out $APP_PKG.$SIM_MAIN
#rm Main.class
#exit 1
# move newly created object files to sgx module
echo "--------------- Moving generated images to SGX module ---------------"
mv /tmp/main_in.o $SGX_DIR/Enclave/graalsgx/
mv /tmp/main_out.o $SGX_DIR/App/graalsgx/

# copy generated headers to sgx module; graal entry points are defined here
mv $SVM_DIR/*.h $SGX_DIR/Include/

# create proxy directories
mkdir -p $SGX_DIR/Enclave/graalsgx/edl
mkdir -p $SGX_DIR/Enclave/graalsgx/proxy
mkdir -p $SGX_DIR/App/graalsgx/proxy

# copy generated files to sgx module: edl files and ecall/ocall definitions and proxies
echo "--------------- Copying generated proxies to SGX module  --------------"
for file in "${EDL_FILES[@]}"; do
    mv $file $SGX_DIR/Enclave/graalsgx/edl
done

for file in "${TRUSTED_PROXIES[@]}"; do
    mv $file $SGX_DIR/Enclave/graalsgx/proxy
done

for file in "${UNTRUSTED_PROXIES[@]}"; do
    mv $file $SGX_DIR/App/graalsgx/proxy
done
# clean other files
rm -fv $SVM_DIR/*.so

# move app folder back to original location
restore_app

# remove generated files
# NB: generated class files have names: InSecurexx, Securexx
# so the regex below should work as long as the above holds
#clean_gen