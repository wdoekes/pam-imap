#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isync.h"

config_t global;
unsigned int Tag = 0;
char Hostname[256];
int Verbose = 0;
int Quiet;

int main (int argc, char *argv[])
{
	char username[16];
	char password[16];
	char *config;
	config = strdup("./isyncrc");
	imap_t *imap = 0;
	int o2o = 0;
	global.port = 993;
	global.box = "INBOX";
	global.folder = "";
	global.require_ssl = 1;
	global.use_tlsv1 = 1;
	global.use_imaps = 1;
	global.host = "localhost";
	load_config(config, &o2o);
	printf("CertificateFile=%s\n", global.cert_file);
	printf("enter username: ");
	scanf("%s", username);
	printf("username: %s\n", username);
	global.user = strdup(username);
	printf("enter password: ");
	scanf("%s", password);
	printf("password: %s\n", password);
	global.pass = strdup(password);
	imap = imap_connect (&global);
	if (imap == 0)
		printf("connect failed!\n");
	else
		printf("connect successfull\n");	
	return 0;

}
