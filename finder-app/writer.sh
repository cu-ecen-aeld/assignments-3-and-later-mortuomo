#!/bin/bash

# check number of args
if [ $# -lt 2 ]
then
    echo "Please provide 2 arguments." >&2
    exit 1
fi

# arg parsing
writefile="$1"
writestr="$2"

# make path to file if doesn't exist
mkdir -p ${writefile%/*}

# create writefile if it doesn't exist
touch "$writefile" || {
    echo "Couldn't create file $writefile" >&2;
    exit 1;
}

# overwrite file contents with provided string
echo "$writestr" > "$writefile"