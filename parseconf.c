/*
* parseconf.c -- utility program for parsing text configuration files
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
#ifndef PARSECONF_C
#define PARSECONF_C
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parseconf.h"

/* this function takes a variable name, and a filename
 * for arguments, and will return the *value* of that
 * variable within a text configuration file
 * Uses the syntax variable = value
 * skips all whitespace and lines starting with '#'
 *
 * Written by Cal Heldenbrand   <calzplace@yahoo.com>
 *	or <heldenca@mnstate.edu>
 */
char * parseconf(const char *variable, const char *filename)
{
	FILE * fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *var_temp = NULL;
	char *ret_val = NULL;
	int i, j;

	fp = fopen(filename, "r");

	while ( (read = getline(&line, &len, fp) ) != -1 )
	{
		if ( line[0] == '#' || line[0] == '\n' )
			continue;
		var_temp = strstr(line, variable);
		if ( var_temp != NULL )
		{  /* found our line */
			/* skip to = sign */
			ret_val = malloc(strlen(var_temp) + 1);
		    memset(ret_val, 0, strlen(var_temp) + 1);
			for ( i = 0 ; var_temp[i] != '=' ; i++) ;
			i++;
			while ( var_temp[i] == ' ' || var_temp[i] == '"' )
				i++;
			for ( j = 0 ; var_temp[i] != '\0' &&
					var_temp[i] != '\n' ; i++, j++)
			{
				ret_val[j] = var_temp[i];
			}
			ret_val[j] = '\0';
			break;
		}
	}
	fclose(fp);
	if ( var_temp != NULL )
	{
		free(var_temp);
		return(ret_val);
	}
	else
		return(NULL);

}
#endif
