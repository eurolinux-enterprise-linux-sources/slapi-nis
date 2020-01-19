/*
 * Copyright 2008 Red Hat, Inc.
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

#include "../../src/config.h"
#include <sys/types.h>
#include <limits.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 4096

struct ldif_entry {
	char *dn;
	char *entry;
};

static int
compare_entries(const void *a, const void *b)
{
	return strcoll(((const struct ldif_entry *) a)->dn,
		       ((const struct ldif_entry *) b)->dn);
}

int
main(int argc, char **argv)
{
	FILE *infile;
	char buf[LINE_MAX], *p;
	struct ldif_entry entry, entries[MAX_ENTRIES];
	size_t n_entries, l;
	memset(&entry, 0, sizeof(entry));
	memset(&entries, 0, sizeof(entries));
	n_entries = 0;
	infile = (argc > 1) ? fopen(argv[1], "r") : stdin;
	while ((infile != NULL) && (fgets(buf, sizeof(buf), infile) != NULL)) {
		if (buf[0] == '#') {
			continue;
		}
		p = strchr(buf, '\n');
		if (p != NULL) {
			if ((p == buf) && (entry.dn != NULL)) {
				if (n_entries <
				    sizeof(entries) / sizeof(entries[0])) {
					lsearch(&entry,
						(void *) &entries,
						&n_entries,
						sizeof(entry),
						&compare_entries);
				}
				memset(&entry, 0, sizeof(entry));
			}
			if (strncasecmp(buf, "dn:", 3) == 0) {
				*p = '\0';
				entry.dn = strdup(buf);
				entry.entry = NULL;
			} else {
				l = (entry.entry ? strlen(entry.entry) : 0) +
				    strlen(buf) + 1;
				p = malloc(l);
				if (p != NULL) {
					if (entry.entry) {
						strcpy(p, entry.entry);
						strcat(p, buf);
					} else {
						strcpy(p, buf);
					}
					free(entry.entry);
					entry.entry = p;
				}
			}
		}
	}
	qsort((void *) &entries, n_entries, sizeof(entry), &compare_entries);
	for (l = 0; l < n_entries; l++) {
		puts(entries[l].dn);
		if (entries[l].entry != NULL) {
			puts(entries[l].entry);
		} else {
			puts("");
		}
	}
	return 0;
}
