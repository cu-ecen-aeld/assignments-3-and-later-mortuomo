#include "aesdsocket.h"

#define THREAD_DUMPFILE_NAME "/tmp/.aesdsocket_"

// if writing to a char device, parts of the code have to be omitted
#if USE_AESD_CHAR_DEVICE /* write to char device */

/**
 * Do nothing and return success. Locking is handled by the char device driver.
 */
static inline int lock_dumpfile(pthread_mutex_t *mutex) { 
	return 0;
}

/**
 * Do nothing and return success. Locking is handled by the char device driver.
 */
static inline int unlock_dumpfile(pthread_mutex_t *mutex) { 
	return 0;
}

/**
 * Do nothing and return success, char device node shall not be removed.
 */
static inline int remove_dumpfile(const char* filename) {
	return 0;
}

/**
 * Do nothing and return success, timestamps would flood the circular buffer.
 */
static inline int timer_setup(timer_t *timerid) {
	return 0; 
}


#else /* write to normal file */

/**
 * Lock mutex of dumpfile. Wrapper of int pthread_mutex_lock()
 */
static inline int lock_dumpfile(pthread_mutex_t *mutex) { 
	return pthread_mutex_lock(mutex);
}

/**
 * Unlock mutex of dumpfile. Wrapper of int pthread_mutex_unlock()
 */
static inline int unlock_dumpfile(pthread_mutex_t *mutex) { 
	return pthread_mutex_unlock(mutex);
}

/**
 * Remove dumpfile, as part of the cleanup. Wrapper of 
 * int remove(const char *__filename)
 */
static inline int remove_dumpfile(const char* filename) {
	return remove(filename);
}

/*
* Helper function to create timer and set its time
* Arguments:
* - timerid: pointer to buffer where to write timer id on creation. Must not be NULL.
*
* Returns:
* - 0 on success
* - last error code otherwise, see errno.h
*/
static int timer_setup(timer_t *timerid) {

	struct sigevent timer_sigevent = { // struct sigevent to pass to timer_create
		.sigev_notify = SIGEV_THREAD, // run function "as if" it was the first function in a dedicated thread
		.sigev_signo = SIGALRM, // not used
		.sigev_value.sival_ptr = &dumpfile_mutex, // argument to pass to timer function
		._sigev_un._sigev_thread = {
			._attribute = NULL,
			._function = timer_func // function to call
		} 
	};
	struct itimerspec timer_spec = { // argument to timer_settime
		.it_interval = { // period over which to run the timer function
			.tv_sec = TIMER_INTERVAL_SECONDS,
			.tv_nsec = 0
		},
		.it_value = { // initial wait to trigger the timer, must not be 0 or the timer is disabled
			.tv_sec = TIMER_INTERVAL_SECONDS,
			.tv_nsec = 0
		}	
	};
	int rc, create_attempts;


	// timerid must not be NULL
	if (NULL == timerid) {
		return EFAULT;
	}

	// create timer
	rc = timer_create(CLOCK_MONOTONIC, &timer_sigevent, timerid);
	for (create_attempts = 0; EAGAIN == rc && create_attempts < MAX_TIMER_CREATE_ATTEMPTS; create_attempts++) {
		sleep(1);
		rc = timer_create(CLOCK_MONOTONIC, &timer_sigevent, timerid);
	}
	if (0 != rc) {
		return rc;
	}

	// set time and arm timer
	rc = timer_settime(*timerid, 0, &timer_spec, NULL);
	if (0 != rc) {
		return rc;
	}

	return EXIT_SUCCESS;
}

/*
* Routine to call every timer expiration 
* Logs timestamp to dumpfile
*/
static void timer_func(union sigval sigval) {

	pthread_mutex_t *dumpfile_mutex;
	FILE *dumpfile_fp;
	time_t raw_time;
	struct tm *local_time;
	int rc;
	char time_string[24];

	if (NULL == sigval.sival_ptr) {
		return;
	}

	dumpfile_mutex = (pthread_mutex_t *) sigval.sival_ptr;



	// try accessing the dumpfile
	rc = lock_dumpfile(dumpfile_mutex);
	if (0 != rc) {
		syslog(LOG_WARNING, "Error %d (%s) on locking dumpfile to print timestamp", rc, strerror(rc));
		return;
	}

	/*
	* ENTERING THE CRITICAL SECTION
	*/

	// open file
	dumpfile_fp = fopen(DUMPFILE_NAME, "a");
	if (NULL == dumpfile_fp) {
		syslog(LOG_ERR, "Error %d (%s) on opening dumpfile to print timestamp", errno, strerror(errno));
		goto unlock_and_exit;
	}

	// get current time
	time(&raw_time);
	local_time = localtime(&raw_time);
	if (0 == strftime(time_string, sizeof(time_string)/sizeof(typeof(*time_string)), "%Y/%m/%d %H:%M:%S", local_time)) {
		syslog(LOG_ERR, "Error formatting current time");
	}
	else { // time formatted properly
		// print timestamp on file
		rc = fprintf(dumpfile_fp, "timestamp:%s\n", time_string);
		if (rc <= 0) {
			syslog(LOG_ERR, "Error on writing timestamp to file %s", DUMPFILE_NAME);
		}
	}

	// close file
	fclose(dumpfile_fp);

	/*
	* LEAVING THE CRITICAL SECTION
	*/

unlock_and_exit:
	unlock_dumpfile(dumpfile_mutex);

	return;
}

#endif /* write to char device or regular file build switch */

static bool signal_to_terminate = false; // starts false, can be set to true by signal handlers
static pthread_mutex_t dumpfile_mutex = PTHREAD_MUTEX_INITIALIZER; // mutex to control access to the dumpfile


// Fetches IP address from sockaddr as human readable string
static int get_ip_as_string_from_sockaddr(struct sockaddr *sockaddr, char *addr_string) {

    // First we need to figure out if it's an IPv4 or IPv6 address
    // so the sockaddr* can be cast to the appropriate data struct
    switch (sockaddr->sa_family) {

        case AF_INET: // IPv4
            if (inet_ntop(AF_INET, &((struct sockaddr_in *)sockaddr)->sin_addr, addr_string, INET_ADDRSTRLEN)
                == NULL) {
                
                sprintf(addr_string, "Bad IPv4 address %x", ((struct sockaddr_in *)sockaddr)->sin_addr.s_addr);
                return E_ON_SOCKET;
            }
            break;

        case AF_INET6: // IPv6
            if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sockaddr)->sin6_addr, addr_string, INET6_ADDRSTRLEN)
                == NULL) {
                sprintf(addr_string, "Bad IPv6 address");
                return E_ON_SOCKET;
                }
            break;

        default:
            sprintf(addr_string, "Unknown address family %i", sockaddr->sa_family);
            return E_ON_SOCKET;
    }

    return 0;
}


/**
 * Read contents of fp and send them over sockfd
 * fp should be rewound and opened for reading by the caller
 * Locking should be handled by the caller
 * @param sockfd: file descriptor of connection over socket
 * @param fp: file pointer to the file to read contents from
 * @returns the number of bytes read from file and sent on socket
 */
static ssize_t send_file_contents(int sockfd, FILE *fp) {

    ssize_t n_bytes_sent = 0, n_bytes_sent_this_iter;
    size_t n_bytes_read = 0;

	char *buf = malloc(sizeof(char) * BUF_SIZE);
	if (NULL == buf) {
		return -ENOMEM;
	}

    if (NULL == fp) {
		free(buf);
        return -ENOENT;
    }

    // keep scanning file until error of EOF
    while (! (feof(fp) || ferror(fp))) {

        // read from file
        n_bytes_read = fread(buf, 1, BUF_SIZE, fp);

        // exit on error
        if (0 == n_bytes_read) {
            break;
        }

        // write buffer on socket
        n_bytes_sent_this_iter = send(sockfd, buf, n_bytes_read, 0);

        if (n_bytes_sent_this_iter <= 0) { // 0 if disconnected, 1 if error
            break;
        }

        n_bytes_sent += n_bytes_sent_this_iter;

    }

	free(buf);
    return n_bytes_sent;
}


/*
* Copies contents of open file "from" (first arg)
* 	into open file "to" (second arg)
*
* Returns number of characters copied
*/
static ssize_t copy_file_contents(FILE *from, FILE* to) {

	int char_to_copy; // fgetc and fputc work with ints, but why? what's the "c" for?
	ssize_t n_chars_copied = 0;

	while ((char_to_copy = fgetc(from)) != EOF) {
		if (EOF == fputc(char_to_copy, to)) {
			break;
		}
		n_chars_copied++;
	}

	return n_chars_copied;
}


/*
 * Signal handler function
 * The main server loop will exit after completing the current iteration
 * upon receiving SIGINT and SIGTERM
 */
static void signal_handler(int signum) {

    switch (signum) {

        case SIGINT:
        case SIGTERM:
            signal_to_terminate = true;
            break;
        default:

    }

    return;
}


/*
* Helper to append a new thread_list_entry to linked list
* Arguments:
* -	head: pointer to thread_list_head, its field first should point to
*	 the first element in the list
* -	tail: pointer to store the new thread_list_entry in linked list
*	 set to NULL if errors occur
*	 the new entry is initialized to zero
*
* Returns:
* - 0 on success, 
* - error code otherwise (see errno.h)
*/
static int append_thread_list_entry(struct thread_list_head *head, struct thread_list_entry **tail) {

	struct thread_list_entry *new_entry;
	int retval;

	if (NULL == head) {
		return EFAULT;
	}


	new_entry = malloc(sizeof(struct thread_list_entry));
	if (NULL == new_entry) {
		// out of memory to process request, clients are gonna have to wait until another thread frees their memory
		retval = ENOMEM;

		// return
	}
	else { // new thread_list_entry successfully allocated

		// append it to the list
		if (NULL == head->first) { // no threads running, set head
			head->first = new_entry;
			*tail = head->first;
		}
		else { // other threads are running, append to last element

			/**
			 * in case tail is NULL for whatever reason, 
			 * find it by moving down the linked list
			 * or tail->next causes a segmentation fault
			 * according to valgrind sometimes tail can point to freed
			 * memory, let's not trust its value anymore and just find it here
			 */
			for (*tail = head->first; (*tail)->next; *tail = (*tail)->next); // head->first cannot be NULL if we're in this branch

			(*tail)->next = new_entry;
			*tail = (*tail)->next;
		}
		
		// just in case
		memset(*tail, 0, sizeof(**tail));

		retval = EXIT_SUCCESS;
	}

	return retval;
}


/**
 * Routine to do based on the packet received
 * The contents of thread_dumpfile_fd are parsed and the specified command is executed.
 * If the packet does not contain a command, it is written to dumpfile_fd.
 * Locking must be handled by the caller.
 * @param thread_dumpfile_fd: buffer where packet are stored before being interpreted
 * @param dumpfile_fd: file where any action specified by the packet is carried on to
 * @returns 0 on success, errno otherwise
 */
int full_packet_routine(FILE *thread_dumpfile_fd, FILE *dumpfile_fd) {

	int retval;
	char *command = NULL; // buffer allocated by fscanf, shall be free'd

	// separate command and arguments from command string in thread_dumpfile
	if (! fscanf(thread_dumpfile_fd, "%m[^:\n]s", &command)) {
		syslog(LOG_ERR, "failed to parse packet");
		return EINVAL;
	}

	//syslog(LOG_DEBUG, "allocated buffer for command at %p, containing %s", command, command);

	// check if it's a command
	if (! strcmp(command, "AESDCHAR_IOCSEEKTO")) {

		struct aesd_seekto args = {0};

		// parse arguments of command
		if (fscanf(thread_dumpfile_fd, ":%d,%d", &args.write_cmd, &args.write_cmd_offset) < 2) {
			syslog(LOG_ERR, "failed to parse arguments for command AESDCHAR_IOCSEEKTO");
			retval = EINVAL;
			goto out;
		}

		// issue ioctl syscall
		if (-1 == ioctl(fileno(dumpfile_fd), AESDCHAR_IOCSEEKTO, &args)) {
			retval = errno;
			syslog(LOG_ERR, "ioctl failed with error %d (%s)", retval, strerror(retval));
			goto out;
		}

		retval = 0;
	}
	else { // default, copy to dumpfile

		ssize_t n_bytes_dumped;

		/**
		 * Rewind back to start, the command buffer matched an arbitrary number of characters
		 * which would be skipped otherwise
		 */
		rewind(thread_dumpfile_fd);

		// dump contents of thread_dumpfile into shared dumpfile
		n_bytes_dumped = copy_file_contents(thread_dumpfile_fd, dumpfile_fd);
		if (0 == n_bytes_dumped) {
			syslog(LOG_ERR, "Couldn't dump packet to file %s.", DUMPFILE_NAME);
			retval = ENOMEM;
			goto out;
		}
		syslog(LOG_DEBUG, "Dumped %li bytes to file %s", n_bytes_dumped, DUMPFILE_NAME);

		/**
		 * reset read cursor on dumpfile. 
		 * do it here so it doesn't affect seek operations done by other commands
		 */ 
		rewind(dumpfile_fd);

		retval = 0;

	} // end of command switch


out:
	if (command) free(command);
	return retval;
}


// function to group the steps to clean up threads, as it will be called both
// in the main loop and at on shutdown
static void cleanup_threads(struct thread_list_head *head, char *ip_addr_string, bool final_cleanup) {

	int rc;
	struct thread_list_entry *prev = NULL, *next;

	for (struct thread_list_entry *entry = head->first; entry; entry = next) { // head->first is linked to entry->next before entry is freed
		// check if it's a real thread, accept might have failed
		if (final_cleanup || 
			entry->thread_data.status != RUNNING) {
			
			if (entry->thread_data.status != NOT_SPAWNED) {
				rc = pthread_join(entry->thread, NULL);
				if (0 != rc) {
					syslog(LOG_ERR, "Error %d (%s) on joining thread %li", rc, strerror(rc), entry->thread);
				}
			}
			

			// close socket
			rc = close(entry->thread_data.connected_sockfd);
			if (0 != rc) {
				syslog(LOG_ERR, 
					"Error %d (%s) on closing connected socket %i", 
					errno, 
					strerror(errno), 
					entry->thread_data.connected_sockfd
				);
			}

			// log message based on thread result 
			get_ip_as_string_from_sockaddr(&(entry->thread_data.peer_addr), ip_addr_string);
			switch (entry->thread_data.status) {
				case (NOT_SPAWNED):
					break;
				case RUNNING:
					syslog(LOG_ERR, "Thread for client %s completed without setting its status flag", ip_addr_string);
					break;
				case (COMPL_SUCCESS):
					syslog(LOG_DEBUG, "Closed connection with %s", ip_addr_string);
					break;
				case (COMPL_ERROR):
					syslog(LOG_ERR, 
						"Error %d (%s) on receiving from %s on port %s",
						entry->thread_data.retval,
						strerror(entry->thread_data.retval),
						ip_addr_string, PORTNO
					);
					break;
				default:
					syslog(LOG_ERR, 
						"Thread for client %s completed with unknown status %d", 
						ip_addr_string, 
						entry->thread_data.status
					);
			}


			// relink the list to exclude the current element
			next = entry->next;
			if (NULL == prev) { // entry is the first element in list
				head->first = next;
			}
			else {
				prev->next = next;
			}

			// clean up dynamically allocated structs
			free(entry);
			
		}
		else { // if the current element is kept, prev moves down to where entry points now
			prev = entry;
			next = entry->next;
		}
	}
}



static void *thread_routine(void *arg) {

	int rc, 
		retval;
	ssize_t n_bytes_received;	// recv return code
	ssize_t n_bytes_sent; // send_file_contents return code, response to client
	size_t n_bytes_dumped;	// fwrite return code
	FILE *dumpfile_fd,	// file pointer to the file where packets are written
		 *thread_dumpfile_fd; // file pointer to dump incomplete packets temporarily, before dumping them to the shared file
	char *receive_buf_cursor, 
		 *receive_buf_cursor_start, // read pointer used while processing received bytes
		 *receive_buf; // buffer to store received bytes to process them
	char thread_dumpfile_name[strlen(THREAD_DUMPFILE_NAME) + 20]; // name of file to dump bytes until a full packet is received
	struct thread_data *thread_data; // thread arg casted as struct thread_data, see header for details
	bool full_packet_received = false;	// set to true when a full packet is received, triggers responding to client


	// cast arg to thread_data to access its properties
	if (NULL == arg) {
		retval = -ENODATA;
		goto exit;
	}
	thread_data = (typeof(thread_data)) arg;
	thread_data->status = RUNNING;

	receive_buf = malloc(sizeof(char) * BUF_SIZE);
	if (NULL == receive_buf) {
		retval = -ENOMEM;
		goto exit;
	}

	// create unique name for thread_dumpfile
	sprintf(thread_dumpfile_name, THREAD_DUMPFILE_NAME "%i", thread_data->connected_sockfd);

	// open thread_dumpfile, and keep it open for the whole duration of the thread
	// so nobody else can mess with it
	// each thread keeps its own file
	// when a full packet is received the file contents are appended to the shared dumpfile
	thread_dumpfile_fd = fopen(thread_dumpfile_name, "w+"); // read/write access, create, truncate
	if (NULL == thread_dumpfile_fd) {
		syslog(LOG_ERR, "Error %d (%s) on opening file %s (temporary storage for incomplete packets).", errno, strerror(errno), thread_dumpfile_name);
		retval = -errno;
		goto free_buffers_and_exit;
	}


	// loop to exhaust receive queue
	n_bytes_received = recv(thread_data->connected_sockfd, receive_buf, BUF_SIZE, 0);
	while (n_bytes_received > 0) { // 0 if disconnected, -1 if error

		syslog(LOG_DEBUG, "Read %li bytes from socket.", n_bytes_received);

		receive_buf_cursor = receive_buf;
		// loop to process received packets in buffer
		while (receive_buf_cursor - receive_buf < n_bytes_received) {

			// move cursor forward until end of packet or end of buffer
			receive_buf_cursor_start = receive_buf_cursor;
			while (*receive_buf_cursor != 10 // LF
				&& *receive_buf_cursor != 13 // CR 
				&& *receive_buf_cursor != 0  // NULL, probably unnecessary
				&&  receive_buf_cursor - receive_buf_cursor_start < n_bytes_received - 1) { // breaks upon reaching the last character in buffer

				receive_buf_cursor++;

			}
			// packets end in a newline character, set flag to later notify sender of received transmission
			if (*receive_buf_cursor == 10 || *receive_buf_cursor == 13) {
				full_packet_received = true;
			}
			// point to next character after terminating character
			// so the number of bytes to write is simply = cursor now - cursor at the start
			receive_buf_cursor++;


			// NOTE: storing incomplete packets on the file is no longer feasible
			// as while a thread releases the lock to receive more bytes
			// another might access the file and send back our incomplete part of packet
			// A way to store incomplete packets until they are completed should be implemented

			// dump packet to thread_dumpfile
			n_bytes_dumped = fwrite(receive_buf_cursor_start, (size_t)(receive_buf_cursor - receive_buf_cursor_start), 1, thread_dumpfile_fd);
			if (0 == n_bytes_dumped) {
				syslog(LOG_ERR, "Couldn't dump packet to file %s.", thread_dumpfile_name);
				// what now???
			}
			syslog(LOG_DEBUG, "Dumped %li bytes to file %s", n_bytes_dumped*(size_t)(receive_buf_cursor - receive_buf_cursor_start), thread_dumpfile_name);

			
			/*
			* If a full packet has been received:
			* -	Dump contents of thread_dumpfile to the shared dumpfile
			* -	Respond to sender, reading the contents of the shared dumpfile
			* This requires the shared file to be locked
			* The thread_dumpfile needs to be truncated for the next cycle
			*/
			if (full_packet_received) {
				// lock mutex
				if ((rc = lock_dumpfile(thread_data->mutex)) != 0) { // error on acquiring the lock
					syslog(LOG_ERR, "Error %d (%s) on locking mutex.", rc, strerror(rc));
					retval = rc;
					goto free_buffers_and_exit;
				}

				/*
				* ENTERING THE CRITICAL SECTION
				* 
				* the thread will block here until mutex is acquired
				*/

				/** 
				 * open dumpfile in read/append mode
				 * the file should be kept open between the write and the read operations
				 * so any seek operation has an effect for the read
				 */
				dumpfile_fd = fopen(DUMPFILE_NAME, "a+");
				if (NULL == dumpfile_fd) {
					syslog(LOG_ERR, "Error %d (%m) on opening file %s.", errno, DUMPFILE_NAME);
					retval = E_ON_SOCKET;

					// don't forget we're in the critical section
					unlock_dumpfile(thread_data->mutex);

					goto close_thread_dumpfile_and_exit;
				}

				// reset read cursor on thread_dumpfile. file needs to stay open to prevent other accesses
				rewind(thread_dumpfile_fd); // pre-copy

				// do the action requested by packet
				if ((rc = full_packet_routine(thread_dumpfile_fd, dumpfile_fd))) {
					syslog(LOG_ERR, "full_packet_routine failed with error %d (%s)", rc, strerror(rc));
					// go ahead, closing files, returning data, waiting for more data
				}

				// reset read cursor on thread_dumpfile. file needs to stay open to prevent other accesses
				rewind(thread_dumpfile_fd); // post-copy, file truncated for the next cycle
				if (ftruncate(fileno(thread_dumpfile_fd), 0)) {
					syslog(LOG_ERR, "error %d (%m) truncating file %s", errno, thread_dumpfile_name);
				}

				/**
				 * keep the lock or some other thread might dump its own packets
				 * and our sender will receive wrong data later
				 */

				/**
				 * keep file open so any seek operations done as part of packet
				 * processing are effective on the next read
				 */

				/**
				 * send back full contents of the file
				 * might take a while and block everything... 
				 */
				n_bytes_sent = send_file_contents(thread_data->connected_sockfd, dumpfile_fd);
				if (n_bytes_sent <= 0) {
					syslog(LOG_ERR, "couldn't read dumpfile and send data on socket");
					retval = E_ON_SOCKET;

					// don't forget we're in the critical section
					fclose(dumpfile_fd);
					unlock_dumpfile(thread_data->mutex);

					goto close_thread_dumpfile_and_exit;
				}
				syslog(LOG_DEBUG, "Sent back %li bytes on socket", n_bytes_sent);

				/*
				* LEAVING THE CRITICAL SECTION
				*
				* make sure every way out of the critical section involves releasing the lock
				*/
				fclose(dumpfile_fd);
				unlock_dumpfile(thread_data->mutex);

				full_packet_received = false;
			}

			// repeat until received bytes are exhausted
			// what do we do with incomplete packets?
		}

		// receive again
		n_bytes_received = recv(thread_data->connected_sockfd, receive_buf, BUF_SIZE, 0);

	}

	// handle loop break conditions
	if (n_bytes_received == 0) { // disconnection
		// log connection closing
		retval = EXIT_SUCCESS;
	}
	else {
		// log error on socket
		retval = ECONNABORTED;
	}


close_thread_dumpfile_and_exit:
	fclose(thread_dumpfile_fd);
	remove(thread_dumpfile_name);
free_buffers_and_exit:
	free(receive_buf);
exit:
	thread_data->retval = retval;

	if (retval == 0) thread_data->status = COMPL_SUCCESS;
	else thread_data->status = COMPL_ERROR;

	return thread_data;
}



int main(int argc, char **argv) {

    int sockfd;
    int rc, retval = E_ON_SOCKET;
    struct addrinfo hints = {0};
    struct addrinfo *servinfo;
    socklen_t peer_addr_size = (socklen_t)sizeof(struct sockaddr);
    char ip_addr_string[INET6_ADDRSTRLEN]; // ip address of client in string form
    struct sigaction sig_action = {0};
	pid_t daemon_pid; // if running as a daemon, contains the pid returned by fork
	struct thread_list_head thread_list_head = { // head of the linked list of threads
		.first = NULL
	};
	struct thread_list_entry *thread_list_tail = NULL; 	// last element in linked list of threads, NULL if no threads are up
	struct pollfd *poll_fds; // struct (or array of structs) containing file descriptor to poll and events to look for
	timer_t timerid = NULL; // id of timer to timestamp dumpfile
    bool 	run_as_daemon = false,
			accept_another;	// can we handle another connection?
    

    // open system logger
    openlog(LOG_IDENT, 0, LOG_USER);

    // setup signal handler
    sig_action.sa_handler = signal_handler;
    rc = sigaction(SIGINT,  &sig_action, NULL);
    if (0 != rc) {
        syslog(LOG_ERR, "Failed to register action to signal SIGINT");
        return E_ON_SOCKET;
    }
    rc = sigaction(SIGTERM, &sig_action, NULL);
    if (0 != rc) {
        syslog(LOG_ERR, "Failed to register action to signal SIGTERM");
        return E_ON_SOCKET;
    }


    /*
     * Parse cmd line arguments
     * -d: set run_as_daemon to true    
    */
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (0 == strcmp("-d", argv[i]))
                run_as_daemon = true;

        }
        
    }

    // Setup hints to create struct sockaddr
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;
    
    /*
     * Create struct addrinfo with parameters in hints
     * the ai_addr field is the struct sockaddr that 
     * will be used later in bind, connect, etc.
     * The first argument is the host IP/hostname as
     * char array, NULL means it is fetched automatically.
     * The struct addrinfo is malloc'd, don't forget to free it!
    */
    rc = getaddrinfo(NULL, PORTNO, &hints, &servinfo);
    if (0 != rc) { // error of some kind
        syslog(LOG_ERR, "Error %d (%s) on address creation.", errno, strerror(errno));
        return E_ON_SOCKET;
    }

    // Create unbound socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd) { // error
        syslog(LOG_ERR, "Error %d (%s) on socket creation.", errno, strerror(errno));
        retval = E_ON_SOCKET;
        goto freeaddrinfo_and_return;
    }

    // bind socket
    rc = bind(sockfd, servinfo->ai_addr, sizeof(*servinfo->ai_addr));
    if (0 != rc) { // error
        syslog(LOG_ERR, "Error %d (%s) on socket binding.", errno, strerror(errno));
        retval = E_ON_SOCKET;
        goto close_socket_and_return;
    }

    // time to fork to the background if running as daemon
    if (run_as_daemon) {
        daemon_pid = fork();
        switch (daemon_pid) {
            case -1: // error
                syslog(LOG_ERR, "Error %d (%s) on forking to run daemon.", errno, strerror(errno));
                retval = E_ON_SOCKET;
                goto close_socket_and_return;

            case 0: // runs in child
                goto main_body; // break would be the same probably

            default: // runs in parent
                syslog(LOG_DEBUG, "Started daemon with pid %i", daemon_pid);
                printf("aesdsocket: Started daemon with pid %i\n", daemon_pid);
                return 0; // we can just leave right???
        }
    }


main_body:
    // listen on socket
    rc = listen(sockfd, BACKLOG);
    if (0 != rc) { // error
        syslog(LOG_ERR, "Error %d (%s) on listen.", errno, strerror(errno));
        retval = E_ON_SOCKET;
        goto close_socket_and_return;
    }

	// create timer to timestamp dumpfile
	rc = timer_setup(&timerid);
	if (0 != rc) {
		syslog(LOG_ERR, "Error %d (%s) on spawning timer", rc, strerror(rc));
		timerid = NULL;
	}

    /*
     * Modify to accept multiple connections, spawning a new thread for each connection
	 * DONE:
     * -    Modify BACKLOG macro in header with the number of connections to accept
     * -    Move the body of the loop, after having accepted a connection, to a function
     * 		 which will be passed to the thread creating function
	 * -	After accepting the connection, spawn a thread running that function
	 * -	Threads should be stored in a singly linked list, see implementation in header. queue.h seemed kinda ugly...
	 * -	The buffer used to read and write packets should only live in the threads.
	 * -	Wait for all threads to finish before gracefully shutting down. A simple join should work.
	 * - 	Implement a thread data structure with all the data to pass to the threads
	 * 		 The struct should probably be dynamically allocated each time a new connection is accepted
	 * 		 How do you know when a thread has finished so you can free it? Check status in thread_data->status
	 * -	Implement a mutex on the dumpfile, each thread will hold the lock while dumping the packet
	 * 		 and sending the content back to client
	 * -	Implement timer to log the time in the dumpfile. Can be in parent main loop or a dedicated thread
	 * 		 not joined at the end.
	 * 
     */

	// set up poll_fds for poll
	poll_fds = malloc(sizeof(poll_fds));
	if (NULL == poll_fds) {
		syslog(LOG_ERR, "Couldn't allocate memory for struct pollfd");
		retval = -ENOMEM;
		goto close_socket_and_return;
	}
	poll_fds->fd = sockfd;
	poll_fds->events = POLLIN | POLLOUT;
	poll_fds->revents = 0;


    // loop to continuously accept connections
    while (! signal_to_terminate) {

		// check if a connection is available without blocking (timeout of 0)
		rc = poll(poll_fds, sizeof(poll_fds)/sizeof(typeof(poll_fds)), 0);
		switch (rc) {
			case -1: // error

				switch (errno) { // but which error
					case EINTR: // interrupted system call
						// it's fine, probably a SIGINT or SIGTERM
						// log debug message and gracefully shutdown
						goto log_signal_and_cleanup;

					default: // an actual error
						// gracefully shutdown
						syslog(LOG_ERR, "Error %d (%s) on polling for connections", errno, strerror(errno));
						goto free_poll_fds_and_exit;
				}
				break; 

			case 0: // no event
				accept_another = false;
				break;

			default: // come event, could also be POLLERR or POLLHUP
				if (poll_fds->revents & poll_fds->events) { // an event we were looking for occurred
					accept_another = true;
				}
				else {
					syslog(LOG_ERR, "Polling for connections returned event mask %i", poll_fds->revents);
					goto join_threads_and_exit;
				}
		}

		/*
		* if a connection is available:
		* - prepare thread_data
		* -	accept it
		* - spawn thread
		*
		* we allocate thread_data first because it's easier not to accept
		*	the connection at all in case of errors, then to have to close the
		*	socket later
		*/

		if (accept_another) {
			
			// prepare to spawn new thread
			// add element to linked list
			rc = append_thread_list_entry(&thread_list_head, &thread_list_tail);
			if (0 != rc) {
				syslog(LOG_ERR, "Error %d (%s) on allocating new struct thread_list_entry", rc, strerror(rc));
			}
			else { // new thread_list_entry successfully created
 
				// accept connection
				thread_list_tail->thread_data.peer_addr.sa_family = AF_INET; // accept seems not to set it, leads to undefined behavior
				thread_list_tail->thread_data.connected_sockfd \
					= accept(sockfd, &(thread_list_tail->thread_data.peer_addr), &peer_addr_size);
				
				if (-1 == thread_list_tail->thread_data.connected_sockfd) { // error on accept
					// thread_list_tail has been allocated for no reason, will be freed later, don't worry

					switch (errno) { // switch case just in case we have more cases in the future
						case EINTR: // interrupted system call
							// it's fine, probably a SIGINT or SIGTERM
							// the code below should handle the graceful shutdown
							break;

						default: // an actual error
							// still no need to shutdown the server, other clients can try to connect
							syslog(LOG_ERR, "Error %d (%s) on accepting connection.", errno, strerror(errno));
					}
				}
				else { // connection successfully accepted
					// log connection success
					get_ip_as_string_from_sockaddr(&(thread_list_tail->thread_data.peer_addr), ip_addr_string);
					syslog(LOG_DEBUG, "Accepted connection from %s", ip_addr_string);

					// set thread_data
					// peer_addr and connected_sockfd should have been set as part of accept
					/*
					* NOTE ON THREAD STATUS
					* If it is set to anything but running before spawning the thread,
					* 	the cleanup function here might be scheduled before the thread has a chance
					*	to set it itself, deleting the thread without doing anything.
					* Set it to NOT_SPAWNED as part of the error handling for pthread_create
					*/
					thread_list_tail->thread_data.status = RUNNING;
					thread_list_tail->thread_data.mutex = &dumpfile_mutex;
					thread_list_tail->thread_data.retval = 0;

					// spawn thread
					rc = pthread_create(&(thread_list_tail->thread), NULL, thread_routine, &(thread_list_tail->thread_data));
					if (0 != rc) { // error
						// we might be out of resources but clients can try again later
						// the cleanup step will close the connected socket and free the allocated memory
						thread_list_tail->thread_data.status = NOT_SPAWNED;
						syslog(LOG_ERR, "Error %d (%s) on spawning new thread for connection.", rc, strerror(rc));
					}
				} // end of connection successfully accepted
			} // end of new_thread_list_entry successfully allocated
		} // end of accept_another == true


		// check status of threads
		// if a thread is complete, join it, clean up its dyn allocated data, remove it from list
		cleanup_threads(&thread_list_head, ip_addr_string, false);

		// give the CPU a little break
		usleep(MAIN_LOOP_SLEEP_USECS);
    }

    // if the main loop has been interrupted we received a signal to terminate
log_signal_and_cleanup:
    syslog(LOG_DEBUG, "Caught signal, exiting...");
    // cleanup steps
join_threads_and_exit:
	// walk down linked list and wait for all threads to finish, cleaning up
	// we have to wait for all of them so a for loop works just fine
	cleanup_threads(&thread_list_head, ip_addr_string, true);
    remove_dumpfile(DUMPFILE_NAME);
free_poll_fds_and_exit:
	free(poll_fds);
close_socket_and_return:
    close(sockfd);
freeaddrinfo_and_return:
    freeaddrinfo(servinfo);
	if (NULL != timerid) timer_delete(timerid);
	closelog();

    return retval;
}