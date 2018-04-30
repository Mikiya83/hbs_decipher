#!/bin/bash

# Dependencies on Mac OS X: 
# greadlink (because readlink -f doesn't work): brew install coreutils 
# Java command line tools: http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jdk-8u172-macosx-x64.dmg

set -e

FULLPATH=$(greadlink -f $0)
CMD=$(basename $FULLPATH)
DIR=$(dirname $FULLPATH)

case $# in
	2) IN=$1; OUT=$2;;
	*) echo Usage: $CMD inputfile outputfile
	   exit 0;;
esac

java -cp "$DIR/bin/hbs.jar:$DIR/lib/*" qnapdecrypt/QNAPFileDecrypter -i $IN  -o $OUT -v

