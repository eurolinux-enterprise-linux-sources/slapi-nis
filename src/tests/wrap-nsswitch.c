/*
 * Copyright 2013 Red Hat, Inc.
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
#define _GNU_SOURCE

#include <sys/types.h>
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int
getpwnam_r(const char *name,
	   struct passwd *resultbuf,
	   char *buffer, size_t buflen,
	   struct passwd **result)
{
	FILE *fp;
	static int (*next)(const char *, struct passwd *,
			   char *, size_t,
			   struct passwd **);
	int error;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getpwnam_r");
	}
	if ((getenv("WRAPPERS_PASSWD") != NULL) &&
	    ((fp = fopen(getenv("WRAPPERS_PASSWD"), "r")) != NULL)) {
		while ((error = fgetpwent_r(fp, resultbuf,
					    buffer, buflen, result)) == 0) {
			if (strcmp(name, resultbuf->pw_name) == 0) {
				fclose(fp);
				return 0;
			}
		}
		fclose(fp);
		if ((error != 0) && (error != ENOENT)) {
			return error;
		}
	}
	return (*next)(name, resultbuf, buffer, buflen, result);
}

struct passwd *
getpwnam(const char *name)
{
	static struct passwd * (*next)(const char *);
	static struct passwd pwd, *pwdp;
	static char *buffer;
	static size_t buflen = 16;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getpwnam");
	}
	if (buffer == NULL) {
		buffer = malloc(buflen);
	}
	if (buffer != NULL) {
	retry:
		switch (getpwnam_r(name, &pwd, buffer, buflen, &pwdp)) {
		case 0:
			return &pwd;
			break;
		case ERANGE:
			free(buffer);
			buffer = malloc((buflen + 1) * 2);
			if (buffer != NULL) {
				buflen = ((buflen + 1) * 2);
				goto retry;
			}
			errno = ERANGE;
			return NULL;
			break;
		}
	}
	if (next == NULL) {
		errno = ENOSYS;
		return NULL;
	}
	return (*next)(name);
}

int
getpwuid_r(uid_t uid,
	   struct passwd *resultbuf,
	   char *buffer, size_t buflen,
	   struct passwd **result)
{
	FILE *fp;
	static int (*next)(uid_t, struct passwd *,
			   char *, size_t,
			   struct passwd **);
	int error;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getpwuid_r");
	}
	if ((getenv("WRAPPERS_PASSWD") != NULL) &&
	    ((fp = fopen(getenv("WRAPPERS_PASSWD"), "r")) != NULL)) {
		while ((error = fgetpwent_r(fp, resultbuf,
					    buffer, buflen, result)) == 0) {
			if (resultbuf->pw_uid == uid) {
				fclose(fp);
				return 0;
			}
		}
		fclose(fp);
		if ((error != 0) && (error != ENOENT)) {
			return error;
		}
	}
	return (*next)(uid, resultbuf, buffer, buflen, result);
}

struct passwd *
getpwuid(uid_t uid)
{
	static struct passwd * (*next)(uid_t);
	static struct passwd pwd, *pwdp;
	static char *buffer;
	static size_t buflen = 16;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getpwuid");
	}
	if (buffer == NULL) {
		buffer = malloc(buflen);
	}
	if (buffer != NULL) {
	retry:
		switch (getpwuid_r(uid, &pwd, buffer, buflen, &pwdp)) {
		case 0:
			return &pwd;
			break;
		case ERANGE:
			free(buffer);
			buffer = malloc((buflen + 1) * 2);
			if (buffer != NULL) {
				buflen = ((buflen + 1) * 2);
				goto retry;
			}
			errno = ERANGE;
			return NULL;
			break;
		}
	}
	if (next == NULL) {
		errno = ENOSYS;
		return NULL;
	}
	return (*next)(uid);
}

int
getgrnam_r(const char *name,
	   struct group *resultbuf,
	   char *buffer, size_t buflen,
	   struct group **result)
{
	FILE *fp;
	static int (*next)(const char *, struct group *,
			   char *, size_t,
			   struct group **);
	int error;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getgrnam_r");
	}
	if ((getenv("WRAPPERS_GROUP") != NULL) &&
	    ((fp = fopen(getenv("WRAPPERS_GROUP"), "r")) != NULL)) {
		while ((error = fgetgrent_r(fp, resultbuf,
					    buffer, buflen, result)) == 0) {
			if (strcmp(name, resultbuf->gr_name) == 0) {
				fclose(fp);
				return 0;
			}
		}
		fclose(fp);
		if ((error != 0) && (error != ENOENT)) {
			return error;
		}
	}
	return (*next)(name, resultbuf, buffer, buflen, result);
}

struct group *
getgrnam(const char *name)
{
	static struct group * (*next)(const char *);
	static struct group grp, *grpp;
	static char *buffer;
	static size_t buflen = 16;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getgrnam");
	}
	if (buffer == NULL) {
		buffer = malloc(buflen);
	}
	if (buffer != NULL) {
	retry:
		switch (getgrnam_r(name, &grp, buffer, buflen, &grpp)) {
		case 0:
			return &grp;
			break;
		case ERANGE:
			free(buffer);
			buffer = malloc((buflen + 1) * 2);
			if (buffer != NULL) {
				buflen = ((buflen + 1) * 2);
				goto retry;
			}
			errno = ERANGE;
			return NULL;
			break;
		}
	}
	if (next == NULL) {
		errno = ENOSYS;
		return NULL;
	}
	return (*next)(name);
}

int
getgrgid_r(gid_t gid,
	   struct group *resultbuf,
	   char *buffer, size_t buflen,
	   struct group **result)
{
	FILE *fp;
	static int (*next)(gid_t, struct group *,
			   char *, size_t,
			   struct group **);
	int error;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getgrgid_r");
	}
	if ((getenv("WRAPPERS_GROUP") != NULL) &&
	    ((fp = fopen(getenv("WRAPPERS_GROUP"), "r")) != NULL)) {
		while ((error = fgetgrent_r(fp, resultbuf,
					    buffer, buflen, result)) == 0) {
			if (resultbuf->gr_gid == gid) {
				fclose(fp);
				return 0;
			}
		}
		fclose(fp);
		if ((error != 0) && (error != ENOENT)) {
			return error;
		}
	}
	return (*next)(gid, resultbuf, buffer, buflen, result);
}

struct group *
getgrgid(gid_t gid)
{
	static struct group * (*next)(gid_t);
	static struct group grp, *grpp;
	static char *buffer;
	static size_t buflen = 16;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getgrgid");
	}
	if (buffer == NULL) {
		buffer = malloc(buflen);
	}
	if (buffer != NULL) {
	retry:
		switch (getgrgid_r(gid, &grp, buffer, buflen, &grpp)) {
		case 0:
			return &grp;
			break;
		case ERANGE:
			free(buffer);
			buffer = malloc((buflen + 1) * 2);
			if (buffer != NULL) {
				buflen = ((buflen + 1) * 2);
				goto retry;
			}
			errno = ERANGE;
			return NULL;
			break;
		}
	}
	if (next == NULL) {
		errno = ENOSYS;
		return NULL;
	}
	return (*next)(gid);
}

int
getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	FILE *fp;
	static int (*next)(const char *, gid_t, gid_t *, int *);
	static char *buffer;
	static size_t buflen = 16;
	struct group grp, *grpp;
	int error, i, count = 0;

	if (next == NULL) {
		next = dlsym(RTLD_NEXT, "getgrouplist");
	}

	if ((getenv("WRAPPERS_GROUP") != NULL) &&
	    ((fp = fopen(getenv("WRAPPERS_GROUP"), "r")) != NULL)) {
		while ((error = fgetgrent_r(fp, &grp,
					    buffer, buflen, &grpp)) == 0) {
			for (i = 0;
			     (grp.gr_mem != NULL) && (grp.gr_mem[i] != NULL);
			     i++) {
				if (strcmp(grp.gr_mem[i], user) == 0) {
					if (count >= *ngroups) {
						*ngroups = count + 1;
						fclose(fp);
						errno = ERANGE;
						return -1;
						break;
					}
					groups[count++] = grp.gr_gid;
				}
			}
		}
		fclose(fp);
		if ((error != 0) && (error != ENOENT)) {
			return error;
		}
		if (count > 0) {
			*ngroups = count;
			return count;
		}
	}
	if (next == NULL) {
		errno = ENOSYS;
		return -1;
	}
	return (*next)(user, group, groups, ngroups);
}
