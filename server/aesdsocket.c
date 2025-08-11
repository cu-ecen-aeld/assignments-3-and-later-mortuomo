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

#include "aesdsocket.h"


bool signal_to_terminate = false; // starts false, can be set to true by signal handlers


// Fetches IP address from sockaddr as human readable string
int get_ip_as_string_from_sockaddr(struct sockaddr *sockaddr, char *addr_string) {

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


// send contents of file *filp over socket sockfd
ssize_t send_file_contents(int sockfd, char *filename) {

    char buf[BUF_SIZE];
    ssize_t n_bytes_sent = 0, n_bytes_sent_this_iter;
    size_t n_bytes_read = 0;
    FILE *fp;

    // open file in read mode
    fp = fopen(filename, "r");
    if (NULL == fp) {
        return -1;
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

    fclose(fp);

    return n_bytes_sent;

}


/*
 * Signal handler function
 * The main server loop will exit after completing the current iteration
 * upon receiving SIGINT and SIGTERM
*/
void signal_handler(int signum) {

    switch (signum) {

        case SIGINT:
            signal_to_terminate = true;
            break;
        case SIGTERM:
            signal_to_terminate = true;
            break;
        default:

    }

    return;
}




int main(int argc, char **argv) {

    int sockfd, connected_sockfd;
    FILE *dumpfile_fd; // file to dump received data
    int rc, retval;
    struct addrinfo hints = {0};
    struct addrinfo *servinfo;
    struct sockaddr *peer_addr;
    socklen_t peer_addr_size = (socklen_t)sizeof(struct sockaddr);
    char receive_buf[BUF_SIZE];
    char dump_buf[BUF_SIZE];
    char *receive_buf_cursor, *receive_buf_cursor_start;
    ssize_t n_bytes_received, n_bytes_sent;
    size_t n_bytes_dumped;
    char ip_addr_string[INET6_ADDRSTRLEN];
    struct sigaction sig_action = {0};
    bool full_packet_received = false, run_as_daemon = false;
    pid_t daemon_pid;

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

    // accept connection
    peer_addr = malloc(sizeof(typeof(*peer_addr)));
    peer_addr->sa_family = AF_INET;

    // loop to continuously accept connections
    while (! signal_to_terminate) {

        connected_sockfd = accept(sockfd, peer_addr, &peer_addr_size);
        if (-1 == connected_sockfd) { // error
            switch (errno) { // switch case just in case we have more cases in the future
                case EINTR: // interrupted system call
                    // probably a SIGINT or SIGTERM
                    // we can still call it a success
                    retval = 0;
                    goto log_signal_and_cleanup;

                default: // an actual error
                    syslog(LOG_ERR, "Error %d (%s) on accepting connection.", errno, strerror(errno));
                    retval = E_ON_SOCKET;
                    goto close_socket_and_return;
            }
        }
        // log connection success
        get_ip_as_string_from_sockaddr(peer_addr, ip_addr_string);
        syslog(LOG_DEBUG, "Accepted connection from %s", ip_addr_string);


        // loop to exhaust receive queue
        n_bytes_received = recv(connected_sockfd, receive_buf, BUF_SIZE, 0);
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
                // packets end in anewline character, set flag to later notify sender of received transmission
                if (*receive_buf_cursor == 10 || *receive_buf_cursor == 13) {
                    full_packet_received = true;
                }
                // point to next character after terminating character
                // so the number of bytes to write is simply = cursor now - cursor at the start
                receive_buf_cursor++; 

                // open dump file in append mode
                dumpfile_fd = fopen(DUMPFILE_NAME, "a");
                if (NULL == dumpfile_fd) {
                    syslog(LOG_ERR, "Error %d (%s) on opening file %s.", errno, strerror(errno), DUMPFILE_NAME);
                    retval = E_ON_SOCKET;
                    goto close_connected_socket_and_return;
                }

                // dump to file
                n_bytes_dumped = fwrite(receive_buf_cursor_start, (size_t)(receive_buf_cursor - receive_buf_cursor_start), 1, dumpfile_fd);
                if (0 == n_bytes_dumped) {
                    syslog(LOG_ERR, "Couldn't dump packet to file %s.", DUMPFILE_NAME);
                    // what now???
                }
                syslog(LOG_DEBUG, "Dumped %li bytes to file %s", n_bytes_dumped*(size_t)(receive_buf_cursor - receive_buf_cursor_start), DUMPFILE_NAME);

                // close file so it's available for reading
                fclose(dumpfile_fd);
                
                if (full_packet_received) {
                    // send back full contents of the file
                    // might take a while and block everything... 
                    n_bytes_sent = send_file_contents(connected_sockfd, DUMPFILE_NAME);
                    if (n_bytes_sent <= 0) {
                        syslog(LOG_ERR, "Couldn't read dump file and send data on socket");
                        retval = E_ON_SOCKET;
                        goto close_connected_socket_and_return;
                    }

                    syslog(LOG_DEBUG, "Sent back %li bytes on socket", n_bytes_sent);

                    full_packet_received = false;
                }
                


                // repeat until received bytes are exhausted
                // what do we do with incomplete packets?
            }

            // receive again
            n_bytes_received = recv(connected_sockfd, receive_buf, BUF_SIZE, 0);

        }

        // handle loop break conditions
        if (n_bytes_received == 0) { // disconnection
            // log connection closing
            syslog(LOG_DEBUG, "Closed connection with %s", ip_addr_string);
            retval = 0;
        }
        else {
            // log error on socket
            syslog(LOG_ERR, "Error %d (%s) on receiving from %s:%s", errno, strerror(errno), ip_addr_string, PORTNO);
            retval = E_ON_SOCKET;
            // open for new connection
        }
    }

    // if the main loop has been interrupted we received a signal to terminate
log_signal_and_cleanup:
    syslog(LOG_DEBUG, "Caught signal, exiting...");
    // cleanup steps
close_connected_socket_and_return: 
    remove(DUMPFILE_NAME);
    close(connected_sockfd);
close_socket_and_return:
    close(sockfd);
    free(peer_addr);
freeaddrinfo_and_return:
    freeaddrinfo(servinfo);

    return retval;
}