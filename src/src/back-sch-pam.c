/* This code is originated from pam_passthru plugin of 389-ds,
 * thus its copyright statement is introduced below: */

/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception.
 *
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
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

#include <security/pam_appl.h>

#include "plugin.h"

/* for third arg to pam_start */
struct conv_data {
	Slapi_PBlock *pb;
	const char *user;
};

static void
free_pam_response(int nresp, struct pam_response *resp)
{
	int ii;
	for (ii = 0; ii < nresp; ++ii) {
		if (resp[ii].resp) {
			free(resp[ii].resp);
		}
	}
	free(resp);
}

/*
 * This is the conversation function passed into pam_start().  This is what sets the password
 * that PAM uses to authenticate.  This function is sort of stupid - it assumes all echo off
 * or binary prompts are for the password, and other prompts are for the username.  Time will
 * tell if this is actually the case.
 */
static int
converse(int num_msg, const struct pam_message **msg,
	 struct pam_response **resp, void *data)
{
	int ii;
	struct berval *creds;
	struct conv_data *conv = data;
	struct pam_response *reply;
	int ret = PAM_SUCCESS;

	if (num_msg <= 0) {
		return PAM_CONV_ERR;
	}

	/* empty reply structure. We have to use malloc/free due to the caller freeing the response */
	reply = calloc(num_msg, sizeof(reply[0]));
	slapi_pblock_get(conv->pb, SLAPI_BIND_CREDENTIALS, &creds); /* the password */
	for (ii = 0; ii < num_msg; ++ii) {
		/* hard to tell what prompt is for . . . */
		/* assume prompts for password are either BINARY or ECHO_OFF */
		switch (msg[ii]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
#ifdef LINUX
		case PAM_BINARY_PROMPT:
#endif
			reply[ii].resp = malloc(creds->bv_len + 1);
			if (reply[ii].resp != NULL) {
				memcpy(reply[ii].resp, creds->bv_val, creds->bv_len);
				reply[ii].resp[creds->bv_len] = '\0';
			} else {
				ret = PAM_CONV_ERR;
			}
			break;
		case PAM_PROMPT_ECHO_ON:
			reply[ii].resp = strdup(conv->user);
			if (reply[ii].resp == NULL) {
				ret = PAM_CONV_ERR;
			}
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			break;
		default:
			ret = PAM_CONV_ERR;
			break;
		}
	}

	if (ret == PAM_CONV_ERR) {
		free_pam_response(num_msg, reply);
		reply = NULL;
	}

	*resp = reply;

	return ret;
}

/* Map a PAM error code to an LDAP error code and text, adding response
 * controls to the given pblock if a control would be suited to the result
 * code. */
static void
map_pam_error(Slapi_PBlock *pb, const char *fn,
	      const char *user, const char *binddn,
	      int rc, int pw_response_requested, pam_handle_t *pamh,
	      char **errmsg, int *retcode)
{
	if (user != NULL) {
		if (rc == PAM_SUCCESS) {
			*errmsg = PR_smprintf("PAM %s succeeds for user \"%s\" "
					      "(bind DN \"%s\")",
					      fn, user, binddn);
		} else {
			if (pamh != NULL) {
				*errmsg = PR_smprintf("PAM %s error for user \"%s\" "
						      "(bind DN \"%s\"): %s",
						      fn, user, binddn, pam_strerror(pamh, rc));
			} else {
				*errmsg = PR_smprintf("PAM %s error for user \"%s\" "
						      "(bind DN \"%s\")",
						      fn, user, binddn);
			}
		}
	} else {
		if (rc == PAM_SUCCESS) {
			*errmsg = PR_smprintf("PAM %s succeeds for user \"%s\" "
					      "(bind DN \"%s\")",
					      fn, user, binddn);
		} else {
			if (pamh != NULL) {
				*errmsg = PR_smprintf("PAM %s error for invalid user "
						      "(bind DN \"%s\"): %s",
						      fn, binddn, pam_strerror(pamh, rc));
			} else {
				*errmsg = PR_smprintf("PAM %s error for invalid user "
						      "(bind DN \"%s\")",
						      fn, binddn);
			}
		}
	}
	switch (rc) {
	case PAM_SUCCESS:
		*retcode = LDAP_SUCCESS;
		break;
	case PAM_USER_UNKNOWN:
		*retcode = LDAP_NO_SUCH_OBJECT;
		break;
	case PAM_AUTH_ERR:
		*retcode = LDAP_INVALID_CREDENTIALS;
		break;
	case PAM_MAXTRIES:
		if (pw_response_requested) {
			slapi_pwpolicy_make_response_control(pb, -1, -1,
							     LDAP_PWPOLICY_ACCTLOCKED);
		}
		*retcode = LDAP_CONSTRAINT_VIOLATION; /* max retries */
		break;
	case PAM_PERM_DENIED:
		if (pw_response_requested) {
			slapi_pwpolicy_make_response_control(pb, -1, -1,
							     LDAP_PWPOLICY_ACCTLOCKED);
		}
		*retcode = LDAP_UNWILLING_TO_PERFORM;
		break;
	case PAM_ACCT_EXPIRED:
	case PAM_NEW_AUTHTOK_REQD:
		slapi_add_pwd_control(pb, LDAP_CONTROL_PWEXPIRED, 0);
		if (pw_response_requested) {
			slapi_pwpolicy_make_response_control(pb, -1, -1,
							     LDAP_PWPOLICY_PWDEXPIRED);
		}
		*retcode = LDAP_INVALID_CREDENTIALS;
		break;
	default:
		*retcode = LDAP_OPERATIONS_ERROR; /* assume config or network problem */
		break;
	}
}

/* Use the supplied simple-bind credentials to attempt PAM authentication as
 * the specified user. */
int
backend_sch_do_pam_auth(Slapi_PBlock *pb, const char *username)
{
	const char *binddn = NULL;
	Slapi_DN *bindsdn = NULL;
	int rc = PAM_SUCCESS;
	int retcode = LDAP_SUCCESS;
	pam_handle_t *pamh = NULL;
	struct conv_data conv_data;
	struct pam_conv conv;
	int pw_response_requested = 0;
	char *errmsg = NULL;
	struct plugin_state *state;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	slapi_pblock_get(pb, SLAPI_PWPOLICY, &pw_response_requested);
	slapi_pblock_get(pb, SLAPI_BIND_TARGET_SDN, &bindsdn);
	if (NULL == bindsdn) {
		errmsg = PR_smprintf("NULL bind dn");
		retcode = LDAP_OPERATIONS_ERROR;
		goto done;
	}
	binddn = slapi_sdn_get_dn(bindsdn);

	memset(&conv_data, 0, sizeof(conv_data));
	conv_data.pb = pb;
	if ((username == NULL) || (strlen(username) == 0)) {
		conv_data.user = "(schema compat plugin invalid bind uid)";
	} else {
		conv_data.user = username;
	}
	memset(&conv, 0, sizeof(conv));
	conv.conv = &converse;
	conv.appdata_ptr = &conv_data;

	rc = pam_start(DEFAULT_PAM_SERVICE, conv_data.user, &conv, &pamh);
	if (rc == PAM_SUCCESS) {
		rc = pam_authenticate(pamh, PAM_SILENT);
		if (rc != PAM_SUCCESS) {
			map_pam_error(pb, "authentication",
				      username, binddn, rc,
				      pw_response_requested != 0,
				      pamh, &errmsg, &retcode);
		} else {
			rc = pam_acct_mgmt(pamh, PAM_SILENT);
			if (rc != PAM_SUCCESS) {
				map_pam_error(pb, "account management",
					      username, binddn, rc,
					      pw_response_requested != 0,
					      pamh, &errmsg, &retcode);
			}
		}
	}

done:
	if ((retcode == LDAP_SUCCESS) && (rc != PAM_SUCCESS)) {
		if (username != NULL) {
			errmsg = PR_smprintf("PAM error for user \"%s\" "
					     "(bind DN \"%s\"): %s",
					     username, binddn, pam_strerror(pamh, rc));
		} else {
			errmsg = PR_smprintf("PAM error for invalid user "
					     "(bind DN \"%s\"): %s",
					     binddn, pam_strerror(pamh, rc));
		}
		retcode = LDAP_OPERATIONS_ERROR;
	}
	if (rc == PAM_SUCCESS) {
		map_pam_error(pb, "authentication and account management",
			      username, binddn, rc,
			      pw_response_requested != 0,
			      pamh, &errmsg, &retcode);
	}
	if (pamh != NULL) {
		pam_end(pamh, rc);
	}

	/* Log the diagnostic information for the administrator. */
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"%s\n", errmsg);
	if (errmsg != NULL) {
		PR_smprintf_free(errmsg);
	}

	/* The client gets a less useful error. */
	if (retcode != LDAP_SUCCESS) {
		slapi_send_ldap_result(pb, retcode, NULL, NULL, 0, NULL);
	}


	return retcode;
}
