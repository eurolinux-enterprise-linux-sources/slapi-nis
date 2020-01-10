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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pthread.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#if defined(USE_NSPR_THREADS) || defined(USE_NSPR_LOCKS)
#include <nspr.h>
#endif

#if defined(USE_PTHREADS) || defined(USE_PTHREAD_LOCKS)
#include <pthread.h>
#endif

#include <rpc/xdr.h>

#include "wrap.h"

struct wrapped_thread {
#if defined(USE_PTHREADS)
	pthread_t tid;
	void *arg;
#elif defined(USE_NSPR_THREADS)
	PRThread *tid;
	struct wrapped_pthread_args {
		void * (*fn)(struct wrapped_thread *);
		void *arg, *result;
	} args;
#else
#error "Unknown threading model!"
#endif
	int stopfd[2];
};

struct wrapped_rwlock {
#if defined(USE_SLAPI_LOCKS)
	Slapi_RWLock *rwlock;
#elif defined(USE_PTHREAD_LOCKS)
	pthread_rwlock_t rwlock;
#elif defined(USE_NSPR_LOCKS)
	PRRWLock *rwlock;
#else
#error "Unknown thread-safe locking model!"
#endif
};

#ifdef USE_NSPR_THREADS
static void
wrap_pthread_starter(void *p)
{
	struct wrapped_thread *t = p;
	t->args.result = t->args.fn(t);
}
#endif

void *
wrap_thread_arg(struct wrapped_thread *t)
{
#ifdef USE_PTHREADS
	return t->arg;
#endif
#ifdef USE_NSPR_THREADS
	return t->args.arg;
#endif
}

struct wrapped_thread *
wrap_start_thread(void * (*fn)(struct wrapped_thread *), void *arg)
{
	struct wrapped_thread *t;
	t = malloc(sizeof(*t));
	if (t == NULL) {
		return NULL;
	}
	memset(t, 0, sizeof(*t));
	if (pipe(t->stopfd) == -1) {
		free(t);
		return NULL;
	}
#ifdef USE_PTHREADS
	t->arg = arg;
	if (pthread_create(&t->tid, NULL, fn, t) != 0) {
		free(t);
		return NULL;
	}
#endif
#ifdef USE_NSPR_THREADS
	t->args.fn = fn;
	t->args.arg = arg;
	t->args.result = NULL;
	t->tid = PR_CreateThread(PR_SYSTEM_THREAD,
				 wrap_pthread_starter, t,
				 PR_PRIORITY_NORMAL,
				 PR_GLOBAL_THREAD,
				 PR_JOINABLE_THREAD,
				 0);
	if (t->tid == NULL) {
		free(t);
		return NULL;
	}
#endif
	return t;
}

void *
wrap_stop_thread(struct wrapped_thread *t)
{
	void *returned = NULL;
#ifdef USE_PTHREADS
	write(t->stopfd[1], "", 1);
	close(t->stopfd[1]);
	pthread_join(t->tid, &returned);
#endif
#ifdef USE_NSPR_THREADS
	write(t->stopfd[1], "", 1);
	close(t->stopfd[1]);
	PR_JoinThread(t->tid);
	returned = t->args.result;
#endif
	free(t);
	return returned;
}

int
wrap_thread_stopfd(struct wrapped_thread *t)
{
	int ret;
#ifdef USE_PTHREADS
	ret = t->stopfd[0];
#endif
#ifdef USE_NSPR_THREADS
	ret = t->stopfd[0];
#endif
	return ret;
}

struct wrapped_rwlock *
wrap_new_rwlock(void)
{
	struct wrapped_rwlock *rwlock;
	rwlock = malloc(sizeof(*rwlock));
	if (rwlock == NULL) {
		return NULL;
	}
#ifdef USE_SLAPI_LOCKS
	rwlock->rwlock = slapi_new_rwlock();
	if (rwlock->rwlock == NULL) {
		free(rwlock);
		return NULL;
	}
#endif
#ifdef USE_PTHREAD_LOCKS
	if (pthread_rwlock_init(&rwlock->rwlock, NULL) != 0) {
		free(rwlock);
		return NULL;
	}
#endif
#ifdef USE_NSPR_LOCKS
	rwlock->rwlock = PR_NewRWLock(PR_RWLOCK_RANK_NONE,
				      PACKAGE_NAME "-rw-lock");
	if (rwlock->rwlock == NULL) {
		free(rwlock);
		return NULL;
	}
#endif
	return rwlock;
}

void
wrap_free_rwlock(struct wrapped_rwlock *rwlock)
{
#ifdef USE_SLAPI_LOCKS
	slapi_destroy_rwlock(rwlock->rwlock);
#endif
#ifdef USE_PTHREAD_LOCKS
	pthread_rwlock_destroy(&rwlock->rwlock);
#endif
#ifdef USE_NSPR_LOCKS
	PR_DestroyRWLock(rwlock->rwlock);
#endif
	free(rwlock);
}

void
wrap_rwlock_rdlock(struct wrapped_rwlock *rwlock)
{
#ifdef USE_SLAPI_LOCKS
	slapi_rwlock_rdlock(rwlock->rwlock);
#endif
#ifdef USE_PTHREAD_LOCKS
	pthread_rwlock_rdlock(&rwlock->rwlock);
#endif
#ifdef USE_NSPR_LOCKS
	PR_RWLock_Rlock(rwlock->rwlock);
#endif
}

void
wrap_rwlock_wrlock(struct wrapped_rwlock *rwlock)
{
#ifdef USE_SLAPI_LOCKS
	slapi_rwlock_wrlock(rwlock->rwlock);
#endif
#ifdef USE_PTHREAD_LOCKS
	pthread_rwlock_wrlock(&rwlock->rwlock);
#endif
#ifdef USE_NSPR_LOCKS
	PR_RWLock_Wlock(rwlock->rwlock);
#endif
}

void
wrap_rwlock_unlock(struct wrapped_rwlock *rwlock)
{
#ifdef USE_SLAPI_LOCKS
	slapi_rwlock_unlock(rwlock->rwlock);
#endif
#ifdef USE_PTHREAD_LOCKS
	pthread_rwlock_unlock(&rwlock->rwlock);
#endif
#ifdef USE_NSPR_LOCKS
	PR_RWLock_Unlock(rwlock->rwlock);
#endif
}

static int
wrap_search_internal_get_entry_cb(Slapi_Entry *e, void *cb)
{
	Slapi_Entry **ret = cb;
	if (*ret) {
		slapi_entry_free(*ret);
	}
	*ret = slapi_entry_dup(e);
	return 0;
}

Slapi_PBlock *
wrap_pblock_new(Slapi_PBlock *parent)
{
	Slapi_PBlock *ret;

	ret = slapi_pblock_new();
#if defined(SLAPI_TXN) && defined(SLAPI_PARENT_TXN)
	if (ret != NULL) {
		void *txn;
		slapi_pblock_get(parent, SLAPI_PARENT_TXN, &txn);
		if (txn != NULL) {
			slapi_pblock_set(ret, SLAPI_PARENT_TXN, txn);
		}
		slapi_pblock_get(parent, SLAPI_TXN, &txn);
		if (txn != NULL) {
			slapi_pblock_set(ret, SLAPI_TXN, txn);
		}
	}
#endif
	return ret;
}

int
wrap_search_internal_get_entry(Slapi_PBlock *parent_pb,
			       Slapi_DN *dn, char *filter, char **attrs,
			       Slapi_Entry **ret_entry, void *caller_id)
{
	Slapi_PBlock *pb;
	int ret;

	*ret_entry = NULL;
	pb = wrap_pblock_new(parent_pb);
	if (pb == NULL) {
		return -1;
	}
	slapi_search_internal_set_pb(pb, slapi_sdn_get_dn(dn), LDAP_SCOPE_BASE,
				     filter ? filter : "(objectClass=*)", attrs,
				     FALSE, NULL, NULL, caller_id, 0);
	ret = slapi_search_internal_callback_pb(pb, ret_entry,
						NULL,
						wrap_search_internal_get_entry_cb,
						NULL);
	slapi_pblock_destroy(pb);
	return ret;
}

static __thread int call_level = 0;

int
wrap_get_call_level(void)
{
	return call_level;
}
int
wrap_inc_call_level(void)
{
	return ++call_level;
}
int
wrap_dec_call_level(void)
{
	return --call_level;
}
