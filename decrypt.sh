#!/bin/bash

case $# in
	2) IN=$1; OUT=$2;;
	*) echo Usage: $0 inputfile outputfile
	   exit 0;;
esac

java -cp "bin/hbs.jar:lib/*" qnapdecrypt/QNAPFileDecrypter -i $IN  -o $OUT -v

