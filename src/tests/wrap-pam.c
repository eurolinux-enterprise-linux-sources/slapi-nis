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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <security/pam_appl.h>

static const struct {
	int value;
	const char *name;
} pam_errors[] = {
	{PAM_SUCCESS, "SUCCESS"},
	{PAM_SUCCESS, "0"},
	{PAM_OPEN_ERR, "OPEN_ERR"},
	{PAM_SYMBOL_ERR, "SYMBOL_ERR"},
	{PAM_SERVICE_ERR, "SERVICE_ERR"},
	{PAM_SYSTEM_ERR, "SYSTEM_ERR"},
	{PAM_BUF_ERR, "BUF_ERR"},
	{PAM_PERM_DENIED, "PERM_DENIED"},
	{PAM_AUTH_ERR, "AUTH_ERR"},
	{PAM_CRED_INSUFFICIENT, "CRED_INSUFFICIENT"},
	{PAM_AUTHINFO_UNAVAIL, "AUTHINFO_UNAVAIL"},
	{PAM_USER_UNKNOWN, "USER_UNKNOWN"},
	{PAM_MAXTRIES, "MAXTRIES"},
	{PAM_NEW_AUTHTOK_REQD, "NEW_AUTHTOK_REQD"},
	{PAM_ACCT_EXPIRED, "ACCT_EXPIRED"},
	{PAM_SESSION_ERR, "SESSION_ERR"},
	{PAM_CRED_UNAVAIL, "CRED_UNAVAIL"},
	{PAM_CRED_EXPIRED, "CRED_EXPIRED"},
	{PAM_CRED_ERR, "CRED_ERR"},
	{PAM_NO_MODULE_DATA, "NO_MODULE_DATA"},
	{PAM_CONV_ERR, "CONV_ERR"},
	{PAM_AUTHTOK_ERR, "AUTHTOK_ERR"},
	{PAM_AUTHTOK_RECOVERY_ERR, "AUTHTOK_RECOVERY_ERR"},
	{PAM_AUTHTOK_LOCK_BUSY, "AUTHTOK_LOCK_BUSY"},
	{PAM_AUTHTOK_DISABLE_AGING, "AUTHTOK_DISABLE_AGING"},
	{PAM_TRY_AGAIN, "TRY_AGAIN"},
	{PAM_IGNORE, "IGNORE"},
	{PAM_ABORT, "ABORT"},
	{PAM_AUTHTOK_EXPIRED, "AUTHTOK_EXPIRED"},
	{PAM_MODULE_UNKNOWN, "UNKNOWN"},
	{PAM_BAD_ITEM, "BAD_ITEM"},
	{PAM_CONV_AGAIN, "CONV_AGAIN"},
	{PAM_INCOMPLETE, "INCOMPLETE"},
};

typedef struct pam_handle {
	char *authtok, errbuf[LINE_MAX];
	struct pam_conv conv;
	int auth, acct;
} pam_handle_t;

static int
pam_numerror(const char *name)
{
	unsigned int i, l;

	for (i = 0; i < sizeof(pam_errors) / sizeof(pam_errors[0]); i++) {
		l = strlen(pam_errors[i].name);
		if (strncasecmp(pam_errors[i].name, name, l) == 0) {
			return pam_errors[i].value;
		}
	}
	return -1;
}

const char *
pam_strerror(pam_handle_t *pamh, int errnum)
{
	unsigned int i;

	for (i = 0; i < sizeof(pam_errors) / sizeof(pam_errors[0]); i++) {
		if (pam_errors[i].value == errnum) {
			return pam_errors[i].name;
		}
	}
	snprintf(pamh->errbuf, sizeof(pamh->errbuf), "PAM error %d", errnum);
	return pamh->errbuf;
}

int
pam_start(const char *service_name, const char *user,
	  const struct pam_conv *pam_conversation, pam_handle_t **pamh)
{
	FILE *fp;
	char buf[LINE_MAX], *p, *q;
	pam_handle_t *ret;

	if (getenv("WRAPPERS_PAM_CREDS") == NULL) {
		return PAM_ABORT;
	}

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		return PAM_BUF_ERR;
	}
	ret->conv = *pam_conversation;

	fp = fopen(getenv("WRAPPERS_PAM_CREDS"), "r");
	if (fp == NULL) {
		free(ret);
		return PAM_ABORT;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\r\n")] = '\0';
		if ((strlen(buf) > strlen(user)) &&
		    (strncmp(user, buf, strlen(user)) == 0) &&
		    (buf[strlen(user)] == ':')) {
			p = buf + strcspn(buf, ":");
			if (*p != '\0') {
				p++;
				q = p + strcspn(p, ":");
				ret->authtok = strndup(p, q - p);
				p = q;
			}
			if (*p != '\0') {
				p++;
				q = p + strcspn(p, ":");
				ret->auth = pam_numerror(p);
				p = q;
			}
			if (*p != '\0') {
				p++;
				q = p + strcspn(p, ":");
				ret->acct = pam_numerror(p);
				p = q;
			}
			break;
		}
	}
	fclose(fp);
	*pamh = ret;
	return PAM_SUCCESS;
}

int
pam_end(pam_handle_t *pamh, int pam_status)
{
	if (pamh == NULL) {
		return PAM_SYSTEM_ERR;
	}
	free(pamh->authtok);
	free(pamh);
	return PAM_SUCCESS;
}

int
pam_authenticate(pam_handle_t *pamh, int flags)
{
	struct pam_response *resp;
	struct pam_message messages[] = {
		{.msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password: "},
	};
	const struct pam_message *msgs = &messages[0];
	int ret;

	resp = NULL;
	if (pamh == NULL) {
		return PAM_SYSTEM_ERR;
	}
	if (pamh->authtok == NULL) {
		return pamh->auth ? pamh->auth : PAM_USER_UNKNOWN;
	}
	if (pamh->conv.conv == NULL) {
		return PAM_CONV_ERR;
	}
	ret = pamh->conv.conv(1, &msgs, &resp, pamh->conv.appdata_ptr);
	if (ret != PAM_SUCCESS) {
		return ret;
	}
	if (strcmp(pamh->authtok, resp->resp) == 0) {
		ret = pamh->auth;
	} else {
		ret = PAM_AUTH_ERR;
	}
	free(resp->resp);
	free(resp);
	return ret;
}

int
pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	if (pamh == NULL) {
		return PAM_SYSTEM_ERR;
	}
	return pamh->acct;
}
