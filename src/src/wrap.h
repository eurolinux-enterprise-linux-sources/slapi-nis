/*
 * Copyright 2008,2010,2012 Red Hat, Inc.
 *
 * This Program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this Program; if not, write to the
 *
 *   Free Software Foundation, Inc.
 *   59 Temple Place, Suite 330
 *   Boston, MA 02111-1307 USA
 *
 */

#ifndef wrap_h
#define wrap_h

struct wrapped_thread;
struct wrapped_rwlock;

struct wrapped_thread * wrap_start_thread(void * (*fn)(struct wrapped_thread *),
					  void *arg);
void *wrap_stop_thread(struct wrapped_thread *t);
void *wrap_thread_arg(struct wrapped_thread *t);
int wrap_thread_stopfd(struct wrapped_thread *t);

struct wrapped_rwlock *wrap_new_rwlock(void);
void wrap_free_rwlock(struct wrapped_rwlock *rwlock);
int wrap_rwlock_rdlock(struct wrapped_rwlock *rwlock);
int wrap_rwlock_wrlock(struct wrapped_rwlock *rwlock);
int wrap_rwlock_unlock(struct wrapped_rwlock *rwlock);

Slapi_PBlock *wrap_pblock_new(Slapi_PBlock *parent);
int wrap_search_internal_get_entry(Slapi_PBlock *pb,
				   Slapi_DN *dn, char *filter, char **attrs,
				   Slapi_Entry **ret_entry, void *caller_id);
int wrap_get_call_level(void);
int wrap_inc_call_level(void);
int wrap_dec_call_level(void);

#endif
