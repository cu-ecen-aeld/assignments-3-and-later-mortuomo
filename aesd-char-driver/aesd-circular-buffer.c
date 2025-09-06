/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer implementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * DONE: implement per description
    */
    
    struct aesd_buffer_entry *entry_rtn = NULL; // entry pointer to iterate over and return at the end
    size_t offset_so_far = 0; // stores the offset from the oldest entry while iterating over entries
    uint8_t index; // index of entry in entry array in buffer, loop variable

    // no segfaults please
    if (NULL == buffer)
        return NULL;


    for (index = buffer->out_offs;
         index != buffer->in_offs || NULL == entry_rtn;
         index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {

        entry_rtn = buffer->entry + index;
        /**
         * increment offset_so_far by the size of the current entry
         * unless we would overshoot the provided char_offset by doing so
         * in that case, we're on the right entry, break loop
         * 
         * NOTE: as the entries are embedded into the buffer, we trust
         *          that dereferencing entry_rtn is never gonna segfault
         *          there are no checks on whether it's NULL, for now
         */
        if (offset_so_far + entry_rtn->size <= char_offset)
            offset_so_far += entry_rtn->size;
        else {
            if (NULL == entry_rtn->buffptr) // no segfaults please
                return entry_rtn;
            if (NULL == entry_offset_byte_rtn)
                return entry_rtn;
            
            // return offset into char buffer at entry
            *entry_offset_byte_rtn = char_offset - offset_so_far;
            // return entry containing it
            return entry_rtn;
        }
    }
    
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * DONE: implement per description
    */
    
    // no segfaults please, trust nobody
    if (NULL == buffer)
        return; // how do you flag an error?

    // as the entry is embedded in the buffer, we have to copy the strcut data into it
    memcpy(buffer->entry + buffer->in_offs, add_entry, sizeof(*buffer->entry));
    // can't do anything about errors anyway  
    
    // move read and write cursors
    if ((buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED == buffer->out_offs) // flag buffer as full if in_offs is about to be equal to out_offs
        buffer->full = true;
    
    if (buffer->full && buffer->out_offs == buffer->in_offs) // move out_offs if buffer is full and in_offs is about to move past out_offs
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; // move in_offs to next entry
    
    return;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
