#!/bin/bash

set -e

FULLPATH=$( cd $(dirname $0); pwd)/$(basename $0)
CMD=$(basename $FULLPATH)
DIR=$(dirname $FULLPATH)

case $# in
	2) IN=$1; OUT=$2;;
	*) echo Usage: $CMD inputfile outputfile
	   exit 0;;
esac

java -jar $DIR/hbs_decipher.jar -i $IN  -o $OUT -v

