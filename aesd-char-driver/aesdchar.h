/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#define AESD_DEBUG 1  //Remove comment on this line to enable debug

#undef PDEBUG             /* undef it, just in case */
#undef PERROR
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#    define PERROR(fmt, args...) printk( KERN_ERR "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#    define PERROR(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#  define PERROR(fmt, args...) /* not debugging: nothing */
#endif

#include "aesd-circular-buffer.h"

#define AESD_PENDING_WRITES_BUF_SIZE 4096 // size of buffers in struct pending_writes_item

struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */
    struct aesd_circular_buffer *circular_buffer;   // circular buffer where data is read/written
    struct aesd_pending_writes_item *pending_writes_head;     // first item in linked list of buffers to store incomplete incoming packets.
    size_t bytes_pending;     // number of bytes stored in pending_writes_items
    struct mutex mutex;  // locking primitive for device
    struct cdev cdev;     /* Char device structure      */
};

/**
 * Linked list of fixed size buffers to hold incomplete incoming packets
 * The buffer must be malloc'd with size PENDING_WRITES_BUF_SIZE
 */
struct aesd_pending_writes_item {
     char *buf;     // buffer to store pending writes data
     struct aesd_pending_writes_item *next;  // next item in linked list
};


#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
