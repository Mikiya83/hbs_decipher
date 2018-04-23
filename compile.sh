#!/bin/bash

set -x

javac -d bin -sourcepath src -cp "lib/commons-cli-1.4.jar:lib/commons-codec-1.11.jar" src/qnapdecrypt/QNAPFileDecrypter.java 


cd bin
mkdir -p META-INF
echo "Main-Class: qnapdecrypt/QNAPFileDecrypter" >META-INF/MANIFEST.MF
jar cvfm hbs.jar META-INF/MANIFEST.MF qnapdecrypt 
cd -

echo java -jar bin/hbs.jar -cp "lib/commons-cli-1.4.jar:lib/commons-codec-1.11.jar"
