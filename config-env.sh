#!/bin/bash
# 
# Author: Peterson Yuhala
# adds mx to path and points java home to jdk-jvmci
#
export PATH=$PWD/mx:$PATH
export JAVA_HOME=$PWD/openjdk1.8.0_282-jvmci-21.1-b01

#echo "PATH=$PATH:/var/test" >> ~/.bashrc