#include "systemcalls.h"
#include <syslog.h>
#include <errno.h>

#define LOG_IDENT "fork_exec_wait"

bool fork_exec_wait(char **command) {

    pid_t child_pid, waited_pid;
    int wstatus;
    int exec_rc;

    openlog(LOG_IDENT, 0, LOG_USER);

    // fork step, return on error
    switch (child_pid = fork()) {

        case -1: // error code on creating child
            syslog(LOG_ERR, "Failed on fork with error %i", errno);
            return false;

        case 0: // this is running in the child process
            syslog(LOG_DEBUG, "Running execv(%s, %s, %s...)", command[0], command[1], command[2]);
            exec_rc = execv(command[0], command);

            syslog(LOG_DEBUG, "execv() returned code %i", exec_rc);
            _exit(exec_rc);
        
        default: // this is running in the caller
            // wait for child, return on error
            waited_pid = waitpid(child_pid, &wstatus, 0);
            if (waited_pid != child_pid) {
                syslog(LOG_ERR, "wait() returned pid %i, expected %i", waited_pid, child_pid);
                return false;
            }

    }

    // this is running in the caller, child has exited after execv
    // check if child has returned normally, and the return code
    if (! WIFEXITED(wstatus) || (0 != WEXITSTATUS(wstatus))) {
        WIFEXITED(wstatus) ? 
            syslog(LOG_ERR, "Pid %i exited with return status %i", waited_pid, WEXITSTATUS(wstatus)) :
            syslog(LOG_ERR, "Pid %i didn't exit properly", waited_pid);
        return false;
    }


    // all error conditions should have been checked
    // and should have returned false
    syslog(LOG_DEBUG, "Completed successfully with return code %i", wstatus);
    return true;
}







/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

    /*
    * DONE  add your code here
    *  Call the system() function with the command set in the cmd
    *   and return a boolean true if the system() call completed with success
    *   or false() if it returned a failure
    */

    int retval = system(cmd);

    return (0 == retval);
}






/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;

    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    //command[count] = command[count];

    /*
    * DONE in fork_exec_wait():
    *   Execute a system command by calling fork, execv(),
    *   and wait instead of system (see LSP page 161).
    *   Use the command[0] as the full path to the command to execute
    *   (first argument to execv), and use the remaining arguments
    *   as second argument to the execv() command.
    *
    */

    va_end(args);

    return fork_exec_wait(command);
}




/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    //command[count] = command[count];


    /*
    * DONE
    *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
    *   redirect standard out to a file specified by outputfile.
    *   The rest of the behaviour is same as do_exec()
    *
    */
    bool retval = false; 
    int fd;

    if (!(fd = open(outputfile, O_WRONLY|O_CREAT))) {
        return false;
    }

    if (dup2(fd, STDOUT_FILENO) < 0) {
        retval = false;
        goto exit;
    }

    retval = fork_exec_wait(command);

exit:
    close(fd);
    return retval;
}
