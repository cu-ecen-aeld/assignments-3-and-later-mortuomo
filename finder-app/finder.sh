#!/bin/sh


# check number of args
if [ $# -lt 2 ]
then
    echo "Please provide 2 arguments." >&2
    exit 1
fi

# assign args
filesdir="$1"
searchstr="$2"

# check if filesdir exists, exit otherwise
if [ ! -d "$filesdir" ]
then
    echo "$filesdir is not a directory" >&2
    exit 1
fi

# store filenames in filesdir and subdirs
files_in_filesdir_and_subdirs=$( find -L "$filesdir" -type f )

# count files in filesdir and subdirectories
n_files_in_filesdir_and_subdirs=0
for _ in $files_in_filesdir_and_subdirs
do 
    n_files_in_filesdir_and_subdirs=$(( $n_files_in_filesdir_and_subdirs + 1 ))
done

# count matches of searchstr within the files
n_matching_files_in_filesdir_and_subdirs=0
for n_matches_in_file in $( grep -c "$searchstr" $files_in_filesdir_and_subdirs 2>/dev/null )
do 
    n_matching_files_in_filesdir_and_subdirs=$(( $n_matching_files_in_filesdir_and_subdirs + ${n_matches_in_file#*:} ))
done

# print results of search
echo "The number of files are $n_files_in_filesdir_and_subdirs and the number of matching lines are $n_matching_files_in_filesdir_and_subdirs"
exit 0



