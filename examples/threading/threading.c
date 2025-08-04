#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

#define max(a, b) (a > b) ? a : b

void* threadfunc(void* thread_param)
{

    int rc; 

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    /*
     * There's no indication on what to return in case of an error,
     * for now thread_param will be returned in all cases.
     * Errors will only be logged.
     */

    // wait to obtain 
    rc = usleep((unsigned int) thread_func_args->wait_to_obtain_ms);
    if (0 != rc) {
        ERROR_LOG("Wait to obtain failed");
        thread_func_args->thread_complete_success = false;
        goto _return;
    }

    // obtain mutex
    rc = pthread_mutex_lock(thread_func_args->mutex);
    if (0 != rc) {
        ERROR_LOG("Couldn't obtain lock");
        thread_func_args->thread_complete_success = false;
        goto _return;
    }
    
    // wait to release
    rc = usleep((unsigned int) thread_func_args->wait_to_release_ms);
    if (0 != rc) {
        ERROR_LOG("Wait to release failed");
        thread_func_args->thread_complete_success = false;
        goto unlock_and_return;
    }

    // everything seemed to work, report success
    thread_func_args->thread_complete_success = true;
    

unlock_and_return:
    // release lock
    pthread_mutex_unlock(thread_func_args->mutex);
    // if it returns an error it's probably already released
    // so whatever, keep going

_return:
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    int rc;
    
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    // Allocate memory for thread data
    struct thread_data *thread_data = (struct thread_data *)malloc(sizeof(struct thread_data));
    if (NULL == thread_data) {
        ERROR_LOG("Failed to allocate memory for struct thread_data");
        return false;
    }

    // Set completed flag to flase
    thread_data->thread_complete_success = false;

    // Setup mutex
    if (NULL == mutex) {
        ERROR_LOG("Argument pthread_mutex_t *mutex is a NULL pointer");
        goto clean_and_return;
    } 
    else {
        thread_data->mutex = mutex;
    }

    // Setup wait times
    if (wait_to_obtain_ms < 0) {
        ERROR_LOG("Argument wait_to_obtain_ms is %i <0, using 0 instead", wait_to_obtain_ms);
    }
    if (wait_to_release_ms < 0) {
        ERROR_LOG("Argument wait_to_release_ms is %i <0, using 0 instead", wait_to_release_ms);
    }
    thread_data->wait_to_obtain_ms = max(0, wait_to_obtain_ms);
    thread_data->wait_to_release_ms = max(0, wait_to_release_ms);

    // Create thread
    rc = pthread_create(thread, NULL, threadfunc, thread_data);
    if (0 != rc) {
        ERROR_LOG("Call to pthread_create failed with error code %i", rc);
        goto clean_and_return;
    }

    // return true at last, everything worked
    return true;


clean_and_return:
    free(thread_data);
    return false;
}

