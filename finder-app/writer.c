#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#define N_ARGS_REQUIRED 2
#define E_NOT_ENOUGH_ARGS 1
#define E_COULDNT_OPEN_FILE 1
#define E_FAIL_ON_WRITE 1
#define E_WROTE_LESS_BYTES 1



int main(int argc, char** argv) {

    int retval = 0;

    // open log
    openlog(NULL, 0, LOG_USER);

    // check number of args
    if (argc < N_ARGS_REQUIRED) {
        syslog(LOG_ERR, "writer: Please provide %d arguments.\n", N_ARGS_REQUIRED);
        return E_NOT_ENOUGH_ARGS;
    }

    // parse args
    char *writefile = argv[1];
    char *writestr = argv[2];

    // open file for writing
    FILE *writefile_fd = fopen(writefile, "w+");
    // check if file was created
    if (NULL == writefile_fd) {
        syslog(LOG_ERR, "Couldn't open file %s\n", writefile);
        return E_COULDNT_OPEN_FILE;
    }

    // write to file
    int bytes_written = fprintf(writefile_fd, "%s", writestr);
    // check for errors
    if ((int)strlen(writestr) != bytes_written) {
        if (bytes_written < 0) { 
            // it's an error code
            syslog(LOG_ERR, "Write operation returned with error %d", bytes_written);
            retval = E_FAIL_ON_WRITE;
        } else {
            // only part of the string was written
            syslog(LOG_ERR, "Requested %li bytes to write, only %d were written\n", strlen(writestr), bytes_written);
            retval = E_WROTE_LESS_BYTES;
        } 
    } else {
        // write succeeded, log success message
        syslog(LOG_DEBUG, "Writing %s to %s.\n", writestr, writefile);
        retval = 0;
    }

    // close file
    fclose(writefile_fd);

    return retval;
}