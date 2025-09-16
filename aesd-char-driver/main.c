/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Stefano Archini"); /** DONE: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

// minimum of two values
//#define min(a, b) ((a < b) ? a : b)

struct aesd_dev aesd_device;

/**
 * PROTOTYPES
 */


static inline struct aesd_pending_writes_item *find_pending_writes_item_at_offset(struct aesd_dev *dev, size_t offset);
static ssize_t copy_from_user_to_pending_buffers(struct aesd_dev *dev, const char __user *buf, size_t count);
static struct aesd_buffer_entry *flush_pending_writes_into_new_entry(struct aesd_dev *dev);
static inline bool is_pending_data_newline_terminated(struct aesd_dev *dev);
static inline void free_pending_writes_items(struct aesd_pending_writes_item *head);
static int aesd_setup_cdev(struct aesd_dev *dev);
int aesd_init_module(void);
void aesd_cleanup_module(void);
int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);



/**
 * Slides down the "pending_writes_item" linked list up to the item where byte offset "offset" is.
 * Locking on dev must be handled by the caller.
 * @param dev: struct aesd_dev to search into, should contain members "pending_writes_head" pointing to the first item of the pending writes linked list,
 * and "bytes_pending" containing the number of bytes currently written into the pending writes linked list.
 * @param offset: byte offset in pending_writes_item linked list to find entry of. 
 * Must not be greater than the number of bytes already written (dev->bytes_pending)
 * @returns The pointer to the struct aesd_pending_writes_item where byte offset is, or NULL in case of errors.
 */
static inline struct aesd_pending_writes_item *find_pending_writes_item_at_offset(struct aesd_dev *dev, size_t offset) {

    int index;
    struct aesd_pending_writes_item *pending_writes_item;

    // make sure offset is legal
    if (offset > dev->bytes_pending) {
        printk(KERN_ERR "aesdchar: offset %zu is larger than bytes_pending %zu in device", offset, dev->bytes_pending);
        return NULL;
    }

    /**
     * Loop to find a spot to write new data
     * init: start iteration count at 0, point to first item in linked list
     * condition: skip all items with full buffers, make sure item is not NULL to avoid segfaults
     * advance: increment iteration count, move down to next item in linked list
     * 
     * NOTE: At least the first item is expected to be there at all times
     */
    for (index = 0, pending_writes_item = dev->pending_writes_head; 
         (index < (offset / AESD_PENDING_WRITES_BUF_SIZE)) && pending_writes_item; 
         index++, pending_writes_item = pending_writes_item->next);
    if (! pending_writes_item) {
        printk(KERN_ERR "aesdchar: offset (%li) and number of items in pending writes linked list (%i) with buffer size (%i) don't match.",
            offset, index, AESD_PENDING_WRITES_BUF_SIZE);
        return NULL;
    }

    // exit success
    return pending_writes_item;
}

/**
 * Copies "count" bytes from user buffer "buf" into pending_writes_item(s) of device "dev".
 * Locking of dev is assumed to be managed by the called
 * @param dev: struct aesd_dev to write into, should contain members "pending_writes_head" pointing to the first item of the pending writes linked list,
 * and "bytes_pending" containing the number of bytes currently written into the pending writes linked list.
 * @param buf: user buffer to copy bytes from
 * @param count: max. number of bytes to copy from buf to dev
 * @returns the number of bytes copied or -errno
 */
static ssize_t copy_from_user_to_pending_buffers(struct aesd_dev *dev, const char __user *buf, size_t count) {

    size_t  bytes_left_to_copy, // tracks rpogress
            bytes_to_copy,  // copy from user n argument
            bytes_not_copied, // copy from user return value
            offset; // offset to write at in pending buffer
    ssize_t retval = 0;
    struct aesd_pending_writes_item *pending_writes_item;   // current item in linked list being used

    /**
     * Find pending_writes_item to start writing to, based on how much data is already written to it
     */
    if (!(pending_writes_item = find_pending_writes_item_at_offset(dev, dev->bytes_pending))) {
        printk(KERN_ERR "aesdchar: failed to find write position %zu in pending_writes_item list", dev->bytes_pending);
        return -EFAULT;
    }

    /**
     * Append new data to buffer.
     * If the buffer would be overflowed, fill it, allocate new item, and write the rest there
     */
    bytes_left_to_copy = count;
    offset = (dev->bytes_pending % AESD_PENDING_WRITES_BUF_SIZE);
    while ((dev->bytes_pending / AESD_PENDING_WRITES_BUF_SIZE) < ((dev->bytes_pending + bytes_left_to_copy) / AESD_PENDING_WRITES_BUF_SIZE)) { // would overflow
        // append new data to the existing data in the buffer until it's filled
        bytes_to_copy = min(bytes_left_to_copy, AESD_PENDING_WRITES_BUF_SIZE - offset);

        /* PERROR("aesd_dev: %p, circular buffer: %p, pending item: %p, buffer in item: %p, copy to: %p, copy from: %p, copy size: %zu", 
            dev, 
            dev->circular_buffer,
            pending_writes_item,
            pending_writes_item->buf,
            pending_writes_item->buf + (dev->bytes_pending % AESD_PENDING_WRITES_BUF_SIZE),
            buf,
            bytes_to_copy
        ); */

        if ((bytes_not_copied = copy_from_user(
                pending_writes_item->buf + offset, 
                buf + retval, bytes_to_copy
            ))) {

            printk(KERN_ERR "aesdchar: copy_from_user failed to copy %zu/%zu bytes", bytes_not_copied, bytes_to_copy);
            return -EFAULT;
        }

        // update bytes pending
        dev->bytes_pending += bytes_to_copy;
        // update bytes written
        retval += bytes_to_copy;
        // update bytes left to write
        bytes_left_to_copy -= bytes_to_copy; // which have been copied at this time

        // allocate new entry
        if (!(pending_writes_item->next = kmalloc(sizeof(pending_writes_item), GFP_KERNEL))) {
            printk(KERN_ERR "aesdchar: failed to allocate memory for struct aesd pending_writes_item after writing %zu/%zu bytes", bytes_to_copy, count);
            return -ENOMEM;
        }
        // move pointer to next item
        pending_writes_item = pending_writes_item->next;
        pending_writes_item->next = NULL;
        // allocate buffer for new entry
        if (!(pending_writes_item->buf = kmalloc(AESD_PENDING_WRITES_BUF_SIZE, GFP_KERNEL))) {
            printk(KERN_ERR "aesdchar: failed to allocate memory for buffer in struct aesd pending_writes_item after writing %zu/%zu bytes", bytes_to_copy, count);
            retval = -ENOMEM;
            goto free_pending_writes_item;
        }

        // start from the begininning of the pending buffer from next iteration
        offset = 0;

        // repeat until all the buffers that had to be filled have been filled
    }
    // finish writing the remaining data, the new list item should be allocated
    if (bytes_left_to_copy) { // in case the writes perfectly filled a buffer, don't waste time trying to copy 0 bytes

        /* PERROR("aesd_dev: %p, circular buffer: %p, pending item: %p, copied so far: %li, copy to: %p, copy from: %p, copy size: %zu", 
            dev, 
            dev->circular_buffer,
            pending_writes_item,
            retval,
            pending_writes_item->buf,
            buf + retval,
            bytes_left_to_copy
        ); */

        // offset into buffer should be 0 if another buffer was filled in the loop, or != 0 if the loop was never entered
        if ((bytes_not_copied = copy_from_user(pending_writes_item->buf + offset, buf + retval, bytes_left_to_copy))) {
            printk(KERN_ERR "aesdchar: copy_from_user failed to copy %zu/%zu bytes", bytes_not_copied, bytes_left_to_copy);
            return -ENOMEM; // nothing is allocated for this, so nothing to free
        }
        // update counts
        dev->bytes_pending += bytes_left_to_copy;
        retval += bytes_left_to_copy;
        return retval;
    }

//free_buffer_in_pending_writes_item:
    kfree(pending_writes_item->buf);
free_pending_writes_item:
    kfree(pending_writes_item);

    return retval;
}

/**
 * Copies all data in pending_writes_item(s) into a new (malloc'd here) aesd_buffer_entry,
 * and frees empty pending_writes_items except the first item.
 * Locking must be handled by the caller.
 * @param dev: struct aesd_dev containing the pending data
 * @returns The pointer to the new entry, or NULL in case of errors.
 */
static struct aesd_buffer_entry *flush_pending_writes_into_new_entry(struct aesd_dev *dev) {

    struct aesd_buffer_entry *new_entry;
    struct aesd_pending_writes_item *pending_writes_item,
                                    *next;
    size_t  bytes_left_to_copy,
            bytes_to_copy;

    // allocate new aesd_buffer_entry
    if (!(new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL))) {
        printk(KERN_ERR "aesdchar: failed to allocate memory for new struct aesd_buffer_entry");
        goto exit_fail;
    }
    // allocate buffer for pending data
    if (!(new_entry->buffptr = kmalloc(dev->bytes_pending * sizeof(*new_entry->buffptr), GFP_KERNEL))) {
        printk(KERN_ERR "aesdchar: failed to allocate memory for buffer of size %li in new_entry", dev->bytes_pending);
        goto free_entry;
    }
    // set size of entry
    new_entry->size = dev->bytes_pending;

    // copy data from pending buffers to entry buffer
    // free everything in the meantime
    bytes_left_to_copy = dev->bytes_pending;
    for (pending_writes_item = dev->pending_writes_head; pending_writes_item; pending_writes_item = next) {
        // copy buffer
        bytes_to_copy = min(bytes_left_to_copy, AESD_PENDING_WRITES_BUF_SIZE);
        if (! memcpy((char *) new_entry->buffptr + dev->bytes_pending - bytes_left_to_copy, pending_writes_item->buf, bytes_to_copy)) {
            printk(KERN_ERR "aesdchar: failed to copy %zu bytes into buffer in new entry at offset %zu", bytes_to_copy, dev->bytes_pending - bytes_left_to_copy);
            goto free_buffer_in_entry;
        }
        // update counts
        bytes_left_to_copy -= bytes_to_copy;
        // store pointer to next item before potentially freeing the current item
        next = pending_writes_item->next;
        // don't free anything on the first entry
        // just delete link to second item, which will be freed later
        if (pending_writes_item != dev->pending_writes_head) {
            kfree(pending_writes_item->buf);
            kfree(pending_writes_item);
        }
        else { // first item
            pending_writes_item->next = NULL;
        }
    }

    // reset pending_bytes
    dev->bytes_pending = 0;

    // exit success
    return new_entry;

free_buffer_in_entry:
    kfree(new_entry->buffptr);
free_entry:
    kfree(new_entry);
exit_fail:
    return NULL;
}

/**
 * True if pending_writes_items are newline or carriage return terminated.
 * @param dev: aesd_dev containing the pending data
 * @returns True if last pending byte is newline or carriage return, false otherwise
 */
static inline bool is_pending_data_newline_terminated(struct aesd_dev *dev) {

    struct aesd_pending_writes_item *pending_writes_item;
    size_t offset = dev->bytes_pending - 1;

    if (dev->bytes_pending == 0) return false;

    // find last entry
    if (!(pending_writes_item = find_pending_writes_item_at_offset(dev, offset))) {
        printk(KERN_ERR "aesdchar: failed to find pending_writes_item at offset %zu", offset);
        return false; // what else can you do
    }

    switch (pending_writes_item->buf[offset % AESD_PENDING_WRITES_BUF_SIZE]) {
        case 10: // LF
        case 13: // CR
            return true;
        default:
            return false;
    }
}

/**
 * Iterate down linkied list of pending writes, freeing all list items and buffers holding pending data.
 * Locking must be handles by the caller.
 * @param head: pointer to the first element of the list
 */
static inline void free_pending_writes_items(struct aesd_pending_writes_item *head) {

    struct aesd_pending_writes_item *curr, *next;

    for (curr = head; curr; curr = next) {

        // avoid NULL pointer issues if htey're even possible
        // buf should be alloc'd at the same time as the entry, should never be a gibberish pointer
        if (curr->buf) kfree(curr->buf);

        // curr->next is not gonna be accessible after we free curr
        next = curr->next;

        // remove references to invalid memory (from the next iteration)
        curr->next = NULL;

        // freedom at last
        kfree(curr);
    }

    return;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    /**
     * DONE: handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * DONE: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;
    ssize_t bytes_not_copied;
    size_t bytes_to_copy;
    size_t offset_in_buffptr;
    struct aesd_dev *dev;
    struct aesd_buffer_entry *entry;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * DONE: handle read
     */
    dev = filp->private_data;

    /**
     * START OF CRITICAL SECTION
     */
    if (mutex_lock_interruptible(&dev->mutex)) {
        // lock attempt was interrupted
        printk(KERN_ERR "aesdchar: mutex_lock_interruptible failed");
        return -ERESTARTSYS;
    }

    /**
     * First use f_pos to determine start position, then handle the first copy
     * 
     * NOTE: read calls everytime for a fixed number of bytes and keeps calling until nothing is read
     *  so there's always a call for f_pos = total of bytes written
     *  entry is NULL in that case, returning an error seems too much, is returning 0 acceptable?
     */
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->circular_buffer, *f_pos, &offset_in_buffptr);

    /* if (! entry) {
        printk(KERN_ERR "aesdchar: can't find entry for f_pos %lld", *f_pos);
        retval = -EFAULT;
        goto unlock;
    } */

    // there is an entry at f_pos, there are bytes to read in that entry, there is a buffer to read those bytes from
    if (entry && entry->size > offset_in_buffptr && entry->buffptr) {
        bytes_to_copy = min(count, entry->size - offset_in_buffptr);
        if ((bytes_not_copied = copy_to_user(buf, entry->buffptr + offset_in_buffptr, bytes_to_copy))) {
            printk(KERN_ERR "aesdchar: copy_to_user failed to copy %zu/%zu bytes", bytes_not_copied, bytes_to_copy);
            retval = -EFAULT;
            goto unlock;
        }

        // increment bytes read and slide f_pos
        retval += bytes_to_copy;
        *f_pos += bytes_to_copy;

        // if less bytes than requested were read, caller will call again
    }
    else { // if for whatever reason there are no bytes to read, return 0.
        retval = 0;
    }

    /**
     * END OF CRITICAL SECTION
     */
unlock:
    mutex_unlock(&dev->mutex);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev;
    struct aesd_buffer_entry *new_entry;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * DONE: handle write
     */
    dev = filp->private_data;

    /**
     * START OF CRITICAL SECTION
     */
    if (mutex_lock_interruptible(&dev->mutex)) {
        // lock attempt was interrupted
        printk(KERN_ERR "aesdchar: mutex_lock_interruptible failed");
        return -ERESTARTSYS;
    }

    /**
     * Append incoming data to pending_writes_item linked list
     * If the last character is a newline, dump pending writes to circular buffer.
     * 
     * NOTE: All the operations should be completed in a single call to avoid race condtions.
     *  If a thread is trying to write a packet that's too long for our buffers, and we return early 
     *  expecting to be called again, another thread might get access first and write
     *  its own packet, which will be appended to the first thread's incomplete packet
     */

    /**
     * Copy user data to pending_writes_item(s)
     * Returns number of bytes copied, therefore the return value of this function
     */
    if (!(retval = copy_from_user_to_pending_buffers(dev, buf, count))) {
        printk(KERN_ERR "aesdchar: failed to copy %zu bytes into pending writes buffer", count);
        goto unlock;
    }

    /**
     * Everything should be copied to the pending buffer here
     * If a newline is terminating the pending data,
     * allocate an appropriately sized buffer, 
     * embed it into an aesd_buffer_entry,
     * add it to the circular buffer,
     * reset the number of pending bytes to 0,
     * clean all pending items but the first.
     * Else return.
     */
    if (is_pending_data_newline_terminated(dev)) {
            
            if (!(new_entry = flush_pending_writes_into_new_entry(dev))) {
                printk(KERN_ERR "aesdchar: failed to create new entry with pending data");
                goto unlock;
            }

            // add new entry to circular buffer
            // CHECK IF BUFFER IS FULL, OLD ENTRY MUST BE FREED
            aesd_circular_buffer_add_entry(dev->circular_buffer, new_entry); // can't possibily fail it seems

            // retval has been set while copying into the pending buffer
            goto unlock;
    }
    // place some frees for all the malloc'd stuff, to jump here in case of errors

    /**
     * END OF CRITICAL SECTION
     */
unlock:
    mutex_unlock(&dev->mutex);


    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "aesdchar: Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * DONE: initialize the AESD specific portion of the device
     */

    // malloc circular buffer member, no submember to malloc after
    if (!(aesd_device.circular_buffer = kmalloc(sizeof(*aesd_device.circular_buffer), GFP_KERNEL))) {
        printk(KERN_ERR "aesdchar: failed to allocate memory for circular buffer");
        result = -ENOMEM;
        goto cleanup;
    }
    memset(aesd_device.circular_buffer, 0, sizeof(*aesd_device.circular_buffer));

    // malloc pending writes head, buf submember should be allocated after
    if (!(aesd_device.pending_writes_head = kmalloc(sizeof(*aesd_device.pending_writes_head), GFP_KERNEL))) {
        printk(KERN_ERR "aesdchar: failed to allocate memory for pending_writes_head");
        result = -ENOMEM;
        goto cleanup;
    }
    memset(aesd_device.pending_writes_head, 0, sizeof(*aesd_device.pending_writes_head));

    // malloc pending_writes_head->buf
    if (!(aesd_device.pending_writes_head->buf = kmalloc(
            sizeof(*aesd_device.pending_writes_head->buf) * AESD_PENDING_WRITES_BUF_SIZE, GFP_KERNEL
        ))) {

        printk(KERN_ERR "aesdchar: failed to allocate memory for pending_writes_head->buf");
        result = -ENOMEM;
        goto cleanup;
    }

    // init mutex
    mutex_init(&aesd_device.mutex);

    // add cdev to kernel, device is live from here
    result = aesd_setup_cdev(&aesd_device);
    if( result ) {
        printk(KERN_ERR "aesdchar: failed to setup cdev (maj %d min %d) with error %d", MAJOR(dev), MINOR(dev), result);
        goto cleanup;
    }

    /* PERROR("aesd_dev: %p, circular buffer: %p, pending head: %p, buffer in head: %p", 
        &aesd_device, 
        aesd_device.circular_buffer, 
        aesd_device.pending_writes_head,
        aesd_device.pending_writes_head->buf
    ); */

    // exit success
    return 0;

cleanup: // in case of failure goto here
    aesd_cleanup_module();
    // exit fail
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    // remove device from kernel, it's no longer live from here
    if (aesd_device.cdev.dev) {
        cdev_del(&aesd_device.cdev);
    }

    /**
     * DONE: cleanup AESD specific poritions here as necessary
     */
    free_pending_writes_items(aesd_device.pending_writes_head);

    if (aesd_device.circular_buffer) {
        kfree(aesd_device.circular_buffer);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
