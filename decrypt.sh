#!/bin/bash

set -e

FULLPATH=$(readlink -f $0)
CMD=$(basename $FULLPATH)
DIR=$(dirname $FULLPATH)

case $# in
	2) IN=$1; OUT=$2;;
	*) echo Usage: $CMD inputfile outputfile
	   exit 0;;
esac

java -cp "$DIR/bin/hbs.jar:$DIR/lib/*" qnapdecrypt/QNAPFileDecrypter -i $IN  -o $OUT -v

