#!/bin/bash

DEV_PATH=$(pwd)
cd tomcat.6080
mkdir webapp
cd webapp
ln -s ../../../security-admin/target/security-admin-web-2.0.0/* .
cd WEB-INF/classes
cp -r ${DEV_PATH}/src/main/resources/conf ./



