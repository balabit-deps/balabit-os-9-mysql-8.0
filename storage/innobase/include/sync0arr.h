/*****************************************************************************

Copyright (c) 1995, 2025, Oracle and/or its affiliates.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License, version 2.0, as published by the
Free Software Foundation.

This program is designed to work with certain software (including
but not limited to OpenSSL) that is licensed under separate terms,
as designated in a particular file or component or in included license
documentation.  The authors of MySQL hereby grant you an additional
permission to link the program and your derivative works with the
separately licensed software that they have either included with
the program or referenced in the documentation.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License, version 2.0,
for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

*****************************************************************************/

/** @file include/sync0arr.h
 The wait array used in synchronization primitives

 Created 9/5/1995 Heikki Tuuri
 *******************************************************/

#ifndef sync0arr_h
#define sync0arr_h

#include "univ.i"

/** Synchronization wait array cell */
struct sync_cell_t;

/** Synchronization wait array */
struct sync_array_t;

/** Get an instance of the sync wait array and reserve a wait array cell in
the instance for waiting for an object. The event of the cell is reset to
nonsignalled state.
If reserving cell of the instance fails, try to get another new instance until
we can reserve an empty cell of it.
@param[in]      object  pointer to the object to wait for
@param[in]      type    lock request type
@param[in]      location        location where requested
@param[out]     cell    the cell reserved, never NULL
@return the sync array found, never NULL. */
static inline sync_array_t *sync_array_get_and_reserve_cell(
    void *object, ulint type, ut::Location location, sync_cell_t **cell);

/** Reserves a wait array cell for waiting for an object.
 The event of the cell is reset to nonsignalled state.
 @param[in] arr wait array
 @param[in] object pointer to the object to wait for
 @param[in] type lock request type
 @param[in] location location where requested
 @return sync cell to wait on*/
sync_cell_t *sync_array_reserve_cell(sync_array_t *arr, void *object,
                                     ulint type, ut::Location location);

/** This function should be called when a thread starts to wait on
 a wait array cell. In the debug version this function checks
 if the wait for a semaphore will result in a deadlock, in which
 case prints info and asserts. */
void sync_array_wait_event(sync_array_t *arr,   /*!< in: wait array */
                           sync_cell_t *&cell); /*!< in: the reserved cell */

/** Frees the cell. NOTE! sync_array_wait_event frees the cell
 automatically! */
void sync_array_free_cell(sync_array_t *arr,   /*!< in: wait array */
                          sync_cell_t *&cell); /*!< in: the reserved cell */

/** Note that one of the wait objects was signalled. */
void sync_array_object_signalled();

/** If the wakeup algorithm does not work perfectly at semaphore releases,
 this function will do the waking (see the comment in mutex_exit). This
 function should be called about every 1 second in the server. */
void sync_arr_wake_threads_if_sema_free();

/** Prints warnings of long semaphore waits to stderr.
 @return true if fatal semaphore wait threshold was exceeded */
bool sync_array_print_long_waits(
    std::thread::id *waiter, /*!< out: longest waiting thread */
    const void **sema);      /*!< out: longest-waited-for semaphore */

void sync_array_detect_deadlock();

/** Prints info of the wait array. */
void sync_array_print(FILE *file); /*!< in: file where to print */

/** Create the primary system wait array(s), they are protected by an OS mutex
 */
void sync_array_init(ulint n_threads); /*!< in: Number of slots to create */

/** Close sync array wait sub-system. */
void sync_array_close();

/** Get an instance of the sync wait array. */
static inline sync_array_t *sync_array_get();

#include "sync0arr.ic"

#endif /* sync0arr_h */
