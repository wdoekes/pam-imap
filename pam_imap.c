/*
* PAM module for Imap
* based on pam_mysql
*
* Copyright (C) 2005 Cal Heldenbrand
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
*
* Modified by Robert Clark <bobby.clark@eku.edu> & Dustin Tennill
<dustin.tennill@eku.edu> (1-19-2001)
* Original Version written by: Gunay ARSLAN
<arslan@gunes.medyatext.com.tr>
* This version by: James O'Kane <jo2y@midnightlinux.com>
* Modifications by Steve Brown, <steve@electronic.co.uk>
*
* Heavy Modifications (90% re-write) by Cal Heldenbrand,
* 	<heldenca@mnstate.edu> or <calzplace@yahoo.com>
* 	for Minnesota State University-Moorhead CSIS department
*
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

#include <errno.h>

#include "parseconf.h"

#ifdef HAVE_CONFIG_H
  #include <config.h>
  #include "config.h"
#endif
#include "isync.h"

#ifdef HAVE_LIBGDBM
  #include <gdbm.h>
#endif

/*  User definable stuff */

   /* Maximum chars that a username may have */
#define MAX_USERNAME 64

   /* Max chars that a password may have */
#define MAX_PASSWORD 48 

    /* Max chars that our domain can have
	 * say.. 26 chars for TLDN, and 26 for a subdomain?
	 */
#define MAX_DOMAIN 52

/*
* here, we make definitions for the externally accessible functions
* in this file (these definitions are required for static modules
* but strongly encouraged generally) they are used to instruct the
* modules include file to define their prototypes.
*/

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#define PAM_MODULE_NAME "pam_imap"
#define PLEASE_ENTER_PASSWORD "IMAP Password:"

#include <security/pam_modules.h>
#include <security/pam_misc.h>

/*  A few defines  */

#define MAX_PATH 256   /*  The maximum bytes for config_file path length */

	/* Globals (YES, I know this is a bad programming practice) */
int critical = 0; /* flag saying in critical code */
int debugp = 0; /* flag saying debugging */
int verbosep = 0; /* flag saying verbose */
const char *pam_passwd = NULL; /* place to remember password
from pam -> imaplib */
const char *pam_username = NULL;
	/* for isync functions */
config_t global;
imap_t *imap = NULL;
char config_file[MAX_PATH];
#ifdef HAVE_LIBGDBM
	GDBM_FILE dbm;  // our global gdbm file pointer
#endif
unsigned int Tag = 0;
char Hostname[256];
int Verbose = 0;
int Quiet;

struct passwd_t {
	char passwd[48];
	struct timeval time;
};


/* Prototypes */

/* PAM conversation function, used for passing PAM
 * structs to the underlying auth system 
 */
int converse (pam_handle_t * pamh,
	int nargs,
	struct pam_message **message,
	struct pam_response **response);

int _set_auth_tok (pam_handle_t * pamh,
	int flags,
	int argc,
	const char **argv);

/* function that queries stdin and asks the user 
 * for a password
 */
int askForPassword(pam_handle_t *pamh);
/* Written by Cal -- take a server number 0 - X,
 * where X is the last server defined in the pam_imap.conf file
 * Will connect, and return a success/fail/timeout value
 *  Read down in the function for return values
 */
int server_connect(int server_number);
int hash_try(void);
void hash_add(void);
char * encryptpwd(const char *pwd);
int db_open();


/*** Cal's prototypes taken from pam_mysql.c ***/

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
		                int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
		                const char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		                const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		                const char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		                const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		                const char **argv);


/***************************************************************************/

/* PAM Authentication function -- used with 'auth' directive */

PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh,
	int flags,
	int argc,
	const char **argv)
{
	int retval, i;
	const char *user;
	char *passwd;
	char *tempstr;
	char *tempstr_save;
	char *userblock;
	int tempfd;
	int o2o = 0;
	imap = NULL;

	/* if this is a successive call, reset our passwords
	 * example:  if the 1st login attempt is incorrect
	 * this will reset all passwd variables to allow
	 * a 2nd input attempt */
	passwd = NULL;
	global.pass = NULL;
	pam_passwd = 0 ;


/*******************  Find config file ****************************/

	if ( argc == 0 )  /* called w/o any args */
	{
		/* assume some general paths */
		if ( (tempfd = open("/etc/pam.d/pam_imap.conf", O_RDONLY) ) != -1 )
		{
			strcpy(config_file, "/etc/pam.d/pam_imap.conf");
			close(tempfd);
		}
		else if ( (tempfd = open("/usr/local/etc/pam_imap.conf", O_RDONLY) ) != -1 )
		{
			strcpy(config_file, "/usr/local/etc/pam_imap.conf");
			close(tempfd);
		}
		/* do we really need any more than this? */
	}
	if ( argc == 1 )
	{  /* argv[0] in the format of conf=/path/filename */
		char * temp_path = malloc( (strlen(argv[0])) + 1);
		strcpy(temp_path, argv[0]);
		if ( (strchr(temp_path, (int) '=') != NULL ) )
		{
			/* get whatever is before the = sign...
			 * will be conf, but we don't care about that */
			strtok(temp_path, "=");
			/*  get whatever is after conf... this is our
			 * filename */
			strcpy(config_file, strtok(NULL, "="));
		}
		else
		{  /* invalid option -- return rudely for now */
			syslog(LOG_ERR, "pam_imap: INVALID module argument");
			/* return PAM_AUTHINFO_UNAVAIL; */
		}
	}
#ifdef DEBUG
	printf("config_file=%s\n", config_file);
#endif


/******************************************************************/
	/* Get User */

	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS || user == NULL)
	{
		syslog (LOG_ERR, "pam_imap: no user specified");
		return PAM_USER_UNKNOWN;
	}
	pam_username = user;

	if (passwd != NULL)
	{
		printf("password is not NULL, resetting\n");
		pam_set_item(pamh, PAM_AUTHTOK, (const void**) &passwd);
	}
	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &passwd);
	if ( passwd == NULL )
		askForPassword(pamh);
	retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &passwd);
	if ( passwd == NULL )
		return PAM_AUTHINFO_UNAVAIL;
	pam_passwd = passwd;
	if ( strcmp(passwd, "") == 0 )
	{ /*  DO we want null passwords?
	   *  Note:  In the future I may provide the option
	   *  to allow NULL pwd's sent, but I don't think it
	   *  would EVER be used ... */
		return PAM_AUTH_ERR;
	}
	/* Check our BlockList for unacceptable users */
	if ( parseconf("PAM_BlockList", config_file) != NULL )
	{
		tempstr_save = parseconf("PAM_BlockList", config_file);
		tempstr = strtok(tempstr_save, ",");
		if ( ! strcmp(tempstr, pam_username) )
		{  /* Found a user that should be blocked! -- first run */
			return PAM_AUTH_ERR;
		}
		while ( (tempstr = strtok(NULL, ",")) != NULL )
		{
			userblock = (char *)malloc(strlen(tempstr) + 1);
			memset(userblock, 0, strlen(tempstr) + 1);
				// skip first blank
			if ( isblank(tempstr[0]) )
				tempstr++;
			strcpy(userblock, tempstr);
			if ( ! strcmp(userblock, pam_username) )
			{  /* Found a user that should be blocked! */
				return PAM_AUTH_ERR;
			}
			free(userblock);
		}
		free(tempstr_save);
	}

/*************************************************************************/

	load_config(config_file, &o2o);
	if ( !global.user )
		global.user = malloc(MAX_USERNAME);
	strncpy(global.user,user, MAX_USERNAME);
	if ( !global.pass )
		global.pass = malloc(MAX_PASSWORD);
	//global.pass = passwd;
	strncpy(global.pass,passwd, MAX_PASSWORD);
    /*  Check to see if we need to add a domain name
	 *  to the username
	 */
    if ( parseconf("PAM_Domain", config_file) != NULL )
	{
		tempstr = parseconf("PAM_Domain", config_file);
		/* for sanity reasons, don't overrun our limits */
		if ( strlen(tempstr) < MAX_DOMAIN )
		{
		    strcat(global.user, "@");
			strcat(global.user, tempstr);
		}
	}

/***********   Hashing cache section ****************/
#ifdef HAVE_LIBGDBM
	if ( ! strcmp(parseconf("PAM_HashEnable", config_file), "yes"))
	{
		if ( hash_try() == PAM_SUCCESS )
			return PAM_SUCCESS;
	}
#endif
/****************************************************/

	for ( i = 0 ;; i++)
	{
		retval = server_connect(i);
#ifdef DEBUG
		printf("server_connect() returned: %d ", retval);
		/* Some extra debug info... this is a common error */
		switch( retval )
		{
			case PAM_SUCCESS:
				printf("PAM_SUCCESS");
				break;
			case PAM_AUTH_ERR:
				printf("PAM_AUTH_ERR");
				break;
			case 1:
				printf("Server Connection Failure");
				break;
			case 2:
				printf("Server Login Failure");
				break;
			case -69:
				printf("No servers left to connect to!");
				break;
			case PAM_CRED_INSUFFICIENT:
				printf("PAM_CRED_INSUFFICIENT");
				break;
		}
		printf("\n");
#endif

		if (retval == PAM_AUTH_ERR)
		{
#ifdef DEBUG
			printf("server_connect() FAIL: %s\n", pam_username);
#endif
			return PAM_AUTH_ERR;
		}
		else if ( retval == 1 )
		{ /* connect failure -- next server */
			continue;
		}
		else if ( retval == -69 )
		{  /* no servers left!  */
			return PAM_AUTHINFO_UNAVAIL;
		}
		else if ( retval == 2)
		{ /* login failure -- exit */
			imap_close(imap);
			pam_passwd = NULL;
			passwd = NULL;
			global.pass = NULL;
			return PAM_AUTH_ERR;
		}
		else
		{  /* login success.  Add to cache and return success */
			imap_close(imap);
#ifdef HAVE_LIBGDBM
			if ( ! strcmp(parseconf("PAM_HashEnable", config_file), "yes"))
				hash_add();
#endif
#ifdef DEBUG
			printf("pam_sm_authenticate: returning PAM_SUCCESS\n");
#endif	
			
			return PAM_SUCCESS;
		}
	}
#ifdef DEBUG
	printf("pam_sm_authenticate: returning PAM_AUTH_ERR\n");
#endif	
	return PAM_AUTH_ERR;

}/* end pam_sm_authenticate */


/* Global PAM functions stolen from other modules */


int converse(pam_handle_t *pamh, int nargs
	, struct pam_message **message
	, struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
	if ( retval == PAM_SUCCESS )
	{
		retval = conv->conv(nargs, ( const struct pam_message ** )message,
				response, conv->appdata_ptr);

		if ((retval != PAM_SUCCESS) && (retval != PAM_CONV_AGAIN))
		{
			syslog(LOG_DEBUG, "pam_imap: conversation failure [%s]",
				pam_strerror(pamh, retval));
		}
	}
	else
	{
		syslog(LOG_ERR, "pam_imap: couldn't obtain coversation function [%s]",
			pam_strerror(pamh, retval));
	}
	return retval; /* propagate error status */
}

int askForPassword(pam_handle_t *pamh)
{
	struct pam_message msg[3], *mesg[3];
	struct pam_response *resp=NULL;
	char *prompt = NULL;
	int i=0;
	int retval;

		msg[i].msg = (char *)parseconf("PAM_PasswordString", config_file);
	msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
	mesg[i] = &msg[0];
	retval = converse(pamh, ++i, mesg, &resp);
	if (prompt)
	{
		_pam_overwrite(prompt);
		_pam_drop(prompt);
	}
	if (retval != PAM_SUCCESS)
	{
		if (resp != NULL)
			_pam_drop_reply(resp,i);
	return ((retval == PAM_CONV_AGAIN) ? PAM_INCOMPLETE:PAM_AUTHINFO_UNAVAIL);
	}

	/* we have a password so set AUTHTOK */
	return pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
}

/***********   Cal's helper functions ***************/

/*  server_connect() -- takes a server number that correlates to
 *  PAM_ServerX and tries to connect to it.
 *
 *  returns:
 *  PAM_SUCCESS when an auth is successful
 *  PAM_AUTH_ERR for something bad in the imap libraries
 *  1 for a server connection failure
 *  2 for a LOGIN failure
 * -69 if there are no servers left to connect to
 *  and PAM_CRED_INSUFFICIENT if something strange happened that
 *  I could not account for
 */

int server_connect(int server_number)
{
	char serv_num[16];
	char num_temp[16];
	char * temp_server;
	char *buffer;
	strcpy(serv_num, "PAM_Server");
	sprintf(num_temp, "%d", server_number);
	strcat(serv_num, num_temp);
	temp_server = parseconf(serv_num, config_file);


	/* return something nobody else will probably use
	 * if there are no servers left */
	if (temp_server == NULL )
		return -69;
	if ( (strstr(temp_server, "imaps:")) != NULL )
	{  /* we have an imaps server */
		global.use_imaps = 1;
		global.require_ssl = 1;
		global.use_sslv2 = 1;
		global.use_sslv3 = 1;
		global.use_tlsv1 = 1;
		strtok(temp_server, ":");
		/* get the hostname */
		buffer = strtok(NULL, ":");
		global.host = buffer;
	}
	else
	{  /* *NOT* an imaps server */
		buffer = strtok(temp_server, ":");
		global.host = buffer;
		global.use_imaps = 0;
	}

	global.box = "INBOX";
	global.folder = "";

	/* get port */
	global.port = atoi(strtok(NULL, ":"));

	global.folder = "";


#ifdef DEBUG
	fflush(stdout);
	printf("********************************\n");
	printf("Debug-Option printout: \n");
	printf("port=%d\n", global.port);
	printf("host=%s\n", global.host);
	printf("box=%s\n", global.box);
	printf("require_ssl=%d\n", global.require_ssl);
	printf("use_imaps=%d\n", global.use_imaps);
	printf("use_sslv2=%d\n", global.use_sslv2);
	printf("use_sslv3=%d\n", global.use_sslv3);
	printf("use_tlsv1=%d\n", global.use_tlsv1);
	printf("cert_file=%s\n", global.cert_file);
	printf("user=%s\n", global.user);
	printf("********************************\n");
	fflush(stdout);
#endif
	imap = imap_connect(&global);

	//  Don't know why this was here!
	//sleep(3);
	if (imap == 0)  /* something happend that I didn't code for */
	{

		syslog (LOG_ERR, "(pam_imap) mail_status -> FAIL");
		syslog (LOG_ERR, pam_username, pam_passwd);
		pam_passwd = NULL;

		pam_passwd = NULL;
#ifdef DEBUG
		printf("imap null error\n");
#endif
		return PAM_AUTH_ERR;
	}
	else if ( imap->error == 1 )
	{ /* connect failure */
		buffer = malloc(256);
		sprintf(buffer, "(pam_imap) SERVER connection failure: %s:%d => %s", global.host, global.port, imap->error_message);
		syslog(LOG_ERR, buffer);
		free(buffer);
#ifdef DEBUG
		printf("connect failure: ");
		printf("%s\n", imap->error_message);
#endif
		return 1;
	}
	else if ( imap->error == 2 )
	{ /* login failure */
		buffer = malloc(256);
		sprintf(buffer, "(pam_imap) LOGIN FAILURE user %s on %s:%d => %s", global.user, global.host, global.port, imap->error_message);
		syslog(LOG_ERR, buffer);
		free(buffer);
#ifdef DEBUG
		printf("login failure");
		printf("%s\n", imap->error_message);
#endif
		return 2;
	}
	else if ( imap->error == 0 )
	{
#ifdef DEBUG
		syslog (LOG_INFO, "(pam_imap) mail_status -> OK for %s", pam_username);
#endif
		return PAM_SUCCESS;
	}
	else
	{  /* something else happened I didn't account for! */
		return PAM_CRED_INSUFFICIENT;

	}

	return 0;

}

#ifdef HAVE_LIBGDBM
	/*  This function uses the global variables "pam_username" and "pam_passwd"
	 *  to cache username/passwd combos based on a delta timeout */
int hash_try()
{
	datum userkey;
	datum passdata;
	struct passwd_t passwd_data;
	struct timeval current;
	int delta_sec;
	char buffer[256];

	delta_sec = atoi( parseconf("PAM_HashDelta", config_file) );

	if ( ! db_open() )
		return PAM_CRED_INSUFFICIENT;

	// check to see if the username key exists
	userkey.dptr = (void *)pam_username;
	userkey.dsize = 17;

	if ( gdbm_exists(dbm, userkey) )
	{
		passdata = gdbm_fetch(dbm, userkey);
		// close as fast as we can to avoid exessive lock times
		gdbm_close(dbm);
		// copy our data back into the struct
		memset(&passwd_data, '\0', sizeof(struct passwd_t));
		memcpy(&passwd_data, passdata.dptr, sizeof(struct passwd_t) );

		// check timestamps
		gettimeofday(&current, NULL);

		if ( (current.tv_sec - passwd_data.time.tv_sec) >= delta_sec )
		{  /* password expired */
  #ifdef DEBUG
			syslog(LOG_INFO, "(pam-imap) cached password stale for %s, using IMAP", pam_username);
  #endif
			return PAM_AUTH_ERR;
		}
		else
		{  /* password good in cache, compare passwords */

			sprintf(buffer, "(pam-imap) using cached password for user %s...  ", userkey.dptr);

			if ( strcmp(pam_passwd, passwd_data.passwd) == 0 )
			//if ( checkpwd(pam_passwd, passwd_data.passwd) )
			{
				strcat(buffer, "    authentication successful\n");
  #ifdef DEBUG
				syslog(LOG_INFO, buffer);
  #endif
				return PAM_SUCCESS;
			}
			else
			{
  #ifdef DEBUG
				strcat(buffer, "    authentication failed\n");
                syslog(LOG_INFO, buffer);
  #endif
				return PAM_AUTH_ERR;
			}
		}

	}
	return PAM_CRED_INSUFFICIENT;
}

	/*  This function is called when we KNOW the IMAP user/pass was successful.
	 *  this adds the user/pass combo with a fresh timestamp to the hash table
	 */
void hash_add()
{
	char *cryptpasswd;
	datum userkey;
	datum passdata;
	struct passwd_t passwd_data;

	cryptpasswd = encryptpwd(pam_passwd);

	// setup username key
	userkey.dptr = (void *) pam_username;
	userkey.dsize = 17;

	// setup passwd_t struct
	memset(&passwd_data, '\0', sizeof(struct passwd_t));
	strcpy(passwd_data.passwd, cryptpasswd);
	gettimeofday( &(passwd_data.time), NULL);
	passdata.dptr = (void *) &passwd_data;
	passdata.dsize = sizeof(struct passwd_t);

	if ( ! db_open() )
		return;

	if ( gdbm_store(dbm, userkey, passdata, GDBM_REPLACE) )
	{
		syslog(LOG_ERR, "gdbm_store error in hash_add(): %s", strerror(errno));
		return;
	}
  #ifdef DEBUG
	syslog(LOG_INFO, "(pam_imap) added user %s to cache", pam_username);
  #endif
	gdbm_close(dbm);

}

// Takes a cleartext string, and returns MD5 encrypted password
char * encryptpwd(const char *pwd)
{
	unsigned long seed[2];
	char salt[] = "$1$........";
	const char *const seedchars =
		"./0123456789ABCDEFGHIJKLMNOPQRST"
		"UVWXYZabcdefghijklmnopqrstuvwxyz";
	int i;

		/* Note that the seed generation was taken from the GNU
		 * libc manual -- if anyone would like to write code
		 * to make a better random seed, please inform me! */

		/* Generate a (not very) random seed.
		You should do it better than this... */
		seed[0] = time(NULL);
		seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

		/* Turn it into printable characters from `seedchars'. */
		for (i = 0; i < 8; i++)
			salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];
	/* return encrypted password */
	return(crypt(pwd, salt));

}
/* Check the password.  pwd = cleartext password to check
 * encryptpwd = the encrypted password to check against
 *
 * returns 1 if the passwords match
 * returns 0 if they do not
 */
int checkpwd(const char *pwd, const char *encryptpwd)
{
	char * result;

	result = crypt(pwd, encryptpwd);

	if ( strcmp(result, encryptpwd) == 0 )
		return 1;
	else
		return 0;
}

/*  Open/close our global gdbm pointer
 *  returns 0 on error, 1 on success
 */
int db_open()
{
	char * hashfile;

	hashfile = parseconf("PAM_HashFile", config_file);

	dbm = gdbm_open(hashfile, (sizeof(struct passwd_t) + 16), GDBM_WRCREAT | GDBM_SYNC | GDBM_NOLOCK, 0600, 0);
	if ( dbm == NULL )
	{
		syslog(LOG_ERR, "gdbm_open error in hash_add(): %s", strerror(errno));
		return 0;
	}
	else
		return 1;

}
#endif  // end HAVE_LIBGDBM

/********************   Other PAM library calls  *****************************/
/*  Note that these functions are not used in the IMAP protocol.
 *  If DEBUG is turned on, they will at least give a message to syslog.
 *  Bottom line, don't use pam_imap for these functions, they all
 *  return SUCCESS.
 */

/* --- account management functions --- */
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t * pamh,
	int flags,
	int argc,
	const char **argv)
{
#ifdef DEBUG
	syslog (LOG_INFO, "pam_imap: acct_mgmt called but not implemented.");
#endif
	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
#ifdef DEBUG
	syslog(LOG_INFO, "pam_imap: setcred called but not implemented.");
#endif
	return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
,const char **argv)
{
#ifdef DEBUG
	syslog(LOG_INFO, "pam_imap: chauthtok called but not implemented.  \
		Password NOT CHANGED!");
#endif
	return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
#ifdef DEBUG
	syslog(LOG_INFO, "pam_imap: open_session called but not implemented.");
#endif
	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
#ifdef DEBUG
	syslog(LOG_INFO, "pam_imap: close_session called but not implemented.");
#endif
	return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
"pam_permit",
pam_sm_authenticate,
pam_sm_setcred,
pam_sm_acct_mgmt,
pam_sm_open_session,
pam_sm_close_session,
pam_sm_chauthtok
};

#endif

