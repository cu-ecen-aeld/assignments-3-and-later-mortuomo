#ifndef AESDSOCKET_H
#define AESDSOCKET_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

#define LOG_IDENT       NULL                        // program identity shown in logs (defaults to the name of the executable)
#define DUMPFILE_NAME   "/var/tmp/aesdsocketdata"   // file to dump received packets to
#define PORTNO          "9000"                      // port to open for listening
#define BACKLOG         5                           // number of clients allowed in queue, others will be turned away
#define E_ON_SOCKET     -1                          // code to return in case of errors
#define BUF_SIZE        256                         // bytes received at a time from socket
#define TIMER_INTERVAL_SECONDS		10				// period for timestamping dumpfile
#define MAX_TIMER_CREATE_ATTEMPTS 	10				// number of retries if timer_creates returns EAGAIN

// way for threads to signal their status
enum thread_status {
	NOT_SPAWNED,
	RUNNING,
	COMPL_SUCCESS,
	COMPL_ERROR
};

// args to pass to the thread routine to run the service
struct thread_data {
    int 				connected_sockfd;   // file descriptor of socket when a connection has been accepted
	struct sockaddr 	peer_addr;			// ip address of connected client
	pthread_mutex_t 	*mutex;				// mutex to control access to the file where packets are dumped
	enum thread_status 	status; 			// flag to check thread status
	int 				retval;				// thread exit value
};

// linked list of threads
struct thread_list_entry {
	pthread_t 					thread; 		// thread handle
	struct thread_data 			thread_data;	// args for thread_function
	struct thread_list_entry	*next;			// next item in linked list
};

// head of linked list
struct thread_list_head {
	struct thread_list_entry 	*first;	// first item in linked list
};


#endif