#!/bin/bash

DEV_PATH=$(pwd)
cd tomcat.6080
mkdir webapp
cd webapp
ln -s ../../../security-admin/target/security-admin-web-2.0.0/* .
cd WEB-INF/classes
cp -r ${DEV_PATH}/src/main/resources/conf ./


#-XX:MetaspaceSize=100m
#-XX:MaxMetaspaceSize=200m
#-Xmx1g
#-Xms1g
#-Xloggc:./logs/gc-worker.log
#-verbose:gc
#-XX:+PrintGCDetails
#-Dproc_rangeradmin
#-Dservername=rangeradmin
#-Dlogdir=./logs


