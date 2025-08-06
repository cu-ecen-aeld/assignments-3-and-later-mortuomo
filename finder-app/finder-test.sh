#!/bin/sh
# Tester script for assignment 1 and assignment 2
# Author: Siddhant Jajoo

set -e
set -u

# Additions for buildroot assignments:
# 	- 	scripts are assumed to be somewhere on PATH rather than the current directory
#		the path where to find the scripts is specified in the SCRIPTS_DIR variable
# 		example: ./writer -> writer
#	-	configuration files are under a specific absolute path and not under the current directory
#		the path is specified in the CONF_DIR_PARENT_PATH variable
#		example: conf/username.txt -> /etc/finder-app/conf/username.txt
#	-	the ouput of the finder command is written to a file
#		the file's path is specified in the FINDER_OUTPUT_FILE variable


NUMFILES=10
WRITESTR=AELD_IS_FUN
WRITEDIR=/tmp/aeld-data
CONF_DIR_PARENT_PATH="/etc/finder-app/"
SCRIPTS_DIR="" # if "" scripts must be on PATH
FINDER_OUTPUT_FILE="/tmp/assignment4-result.txt"
username=$(cat ${CONF_DIR_PARENT_PATH}/conf/username.txt)


if [ $# -lt 3 ]
then
	echo "Using default value ${WRITESTR} for string to write"
	if [ $# -lt 1 ]
	then
		echo "Using default value ${NUMFILES} for number of files to write"
	else
		NUMFILES=$1
	fi	
else
	NUMFILES=$1
	WRITESTR=$2
	WRITEDIR=/tmp/aeld-data/$3
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

rm -rf "${WRITEDIR}"

# create $WRITEDIR if not assignment1
assignment=`cat ${CONF_DIR_PARENT_PATH}/conf/assignment.txt`

if [ $assignment != 'assignment1' ]
then
	mkdir -p "$WRITEDIR"

	#The WRITEDIR is in quotes because if the directory path consists of spaces, then variable substitution will consider it as multiple argument.
	#The quotes signify that the entire string in WRITEDIR is a single string.
	#This issue can also be resolved by using double square brackets i.e [[ ]] instead of using quotes.
	if [ -d "$WRITEDIR" ]
	then
		echo "$WRITEDIR created"
	else
		exit 1
	fi
fi
#echo "Removing the old writer utility and compiling as a native application"
#make clean
#make

for i in $( seq 1 $NUMFILES)
do
	${SCRIPTS_DIR}writer "$WRITEDIR/${username}$i.txt" "$WRITESTR"
done

OUTPUTSTRING=$(${SCRIPTS_DIR}finder.sh "$WRITEDIR" "$WRITESTR")

# write OUTPUTSTRING to file
echo "${OUTPUTSTRING}" > ${FINDER_OUTPUT_FILE}

# remove temporary directories
rm -rf /tmp/aeld-data

set +e
echo ${OUTPUTSTRING} | grep "${MATCHSTR}"
if [ $? -eq 0 ]; then
	echo "success"
	exit 0
else
	echo "failed: expected  ${MATCHSTR} in ${OUTPUTSTRING} but instead found"
	exit 1
fi
