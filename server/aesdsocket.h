#ifndef AESDSOCKET_H
#define AESDSOCKET_H


#define LOG_IDENT       NULL                        // program identity shown in logs (defaults to the name of the executable)
#define DUMPFILE_NAME   "/var/tmp/aesdsocketdata"   // file to dump received packets to
#define PORTNO          "9000"                      // port to open for listening
#define BACKLOG         1                           // number of clients allowed in queue, others will be turned away
#define E_ON_SOCKET     -1                          // code to return in case of errors
#define BUF_SIZE        256                         // bytes received at a time from socket



#endif