#include <stdlib.h>
#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif
#include <string.h>
#include <ctype.h>

#include "isync.h"

void
infoc (char c)
{
    if (!Quiet)
	putchar (c);
}
void
info (const char *msg, ...)
{
  va_list va;

  if (!Quiet)
  {
    va_start (va, msg);
    vprintf (msg, va);
    va_end (va);
  }
}

char *
next_arg (char **s)
{
    char *ret;

    if (!s)
	return 0;
    if (!*s)
	return 0;
    while (isspace ((unsigned char) **s))
	(*s)++;
    if (!**s)
    {
	*s = 0;
	return 0;
    }
    if (**s == '"')
    {
	++*s;
	ret = *s;
	*s = strchr (*s, '"');
    }
    else
    {
	ret = *s;
	while (**s && !isspace ((unsigned char) **s))
	    (*s)++;
    }
    if (*s)
    {
	if (**s)
	    *(*s)++ = 0;
	if (!**s)
	    *s = 0;
    }
    return ret;
}
