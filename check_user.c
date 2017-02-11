/*
* check_user.c -- utility program testing user authentication
*
*  Please look at ./conf/check_user, and add this file to
*	/etc/pam.d/   or... change /etc/pam.conf accordingly
*
* Copyright (C) 2003 Cal Heldenbrand
*	<heldenca@mnstate.edu> or <calzplace@users.sf.net>
*
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>



static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    pam_handle_t *pamh;
    int retval, acct_retval;
    char *user;
    char *service;
    pamh = NULL;


    if(argc == 1)
    {
        fprintf(stderr, "Usage: check_user <username> [service]\n");
	fprintf(stderr, "where username is, well, username.\n");
	fprintf(stderr, "and service is the pam service in /etc/pam.d/<service>\n");
	fprintf(stderr, "default service is 'check_user'\n");
        exit(1);
    }

    if(argc > 1)
    {
        user = argv[1];
    }
    if(argc == 3)
    {
	service = argv[2];
	printf("using service \"%s\"\n", service);
    }
    else
    {
	service = strdup("check_user");
    }


    fprintf(stdout, "user=%s\n", user);

    retval = pam_start(service, user, &conv, &pamh);

    if (retval != PAM_SUCCESS )
    {
    	printf("check_user: Unable to start pam: pam_start() returned %d\n",
		retval);
	exit(1);
	
    }
        retval = pam_authenticate(pamh, 0);    /* is user really user? */
	printf("check_user: pam_authenticate() returned: %d: ", retval);
	switch (retval)
	{
		case PAM_DISALLOW_NULL_AUTHTOK:
			printf("PAM_DISALLOW_NULL_AUTHTOK\n");
			break;
		case PAM_AUTH_ERR:
			printf("PAM_AUTH_ERR\n");
			break;
		case PAM_CRED_INSUFFICIENT:
			printf("PAM_CRED_INSUFFICIENT\n");
			break;
		case PAM_AUTHINFO_UNAVAIL:
			printf("PAM_AUTHINFO_UNAVAIL\n");
			break;
		case PAM_USER_UNKNOWN:
			printf("PAM_USER_UNKNOWN\n");
			break;
		case PAM_MAXTRIES:
			printf("PAM_MAXTRIES\n");
			break;
		case PAM_SUCCESS:
			printf("PAM_SUCCESS\n");
			break;
		default:
			printf("Returned something else! value=%d\n", retval);
			break;
	}
    acct_retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */
    /* This is where we have been authorized or not. */
    printf("\ncheck_user end result:\n");
    printf("########################\n");
    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "Authenticated\n");
    } else {
        fprintf(stdout, "Not Authenticated\n");
    }

    if ( acct_retval == PAM_SUCCESS)
    {
	fprintf(stdout, "Account Authorized\n");
    }
    else
    {
	fprintf(stdout, "Account Not Authorized, error = %d\n", acct_retval);
        fprintf(stdout, "\t(This is OK if checking pam_imap functionality)\n");
    }
    printf("########################\n");
    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}

