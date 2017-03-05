/* $OpenBSD: ssh-store.c,v 1.89 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * ssh-store.c by Tim Adye <T.J.Adye@rl.ac.uk>, based on ssh-add.c.
 *
 * ssh-add.c:-
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Adds an identity to the authentication server, or removes an identity.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <openssl/evp.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "rsa.h"
#include "log.h"
#include "key.h"
#include "buffer.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "misc.h"

/* argv0 */
extern char *__progname;
#define CHUNK 1024

int
set_from_file(AuthenticationConnection *auth, const char *var, u_int lvar, const char *file)
{
  FILE *f;
  char *val = NULL;
  u_int lval = 0;
  size_t n;
  int ret;

  if (file && 0 != strcmp (file, "-")) {
    f = fopen (file, "r");
    if (!f) {
      fprintf (stderr, "%s: could not open %s\n", __progname, file);
      return 3;
    }
  } else {
    f = stdin;
  }
  lval = 0;
  do {
    val= xrealloc (val, lval+CHUNK, 1);
    n = fread (val+lval, 1, CHUNK, f);
    lval += n;
  } while (n == CHUNK);
  if (lval > 0 && val[lval-1] == '\n') lval--;
  ret = ssh_set_variable (auth, var, lvar, val, lval);
  free (val);
  return ret;
}

static int
print_variable(AuthenticationConnection *auth, const char *var, u_int lvar)
{
	int ret = 0;
  char *val;
  u_int lval;

  ret = ssh_get_variable(auth, var, lvar, &val, &lval);
  if (ret && val) {
    fwrite (val, 1, lval, stdout);
    putchar ('\n');
    free(val);
  }
	return ret;
}

static int
list_variables(AuthenticationConnection *ac, const char* prefix, u_int lprefix, char full)
{
	char *var, *val;
  u_int lvar, lval;
	int ok, nvars = 0;

  for (ok = ssh_get_first_variable(ac, prefix, lprefix, full, &var, &lvar, &val, &lval);
       ok;
       ok = ssh_get_next_variable(ac, full, &var, &lvar, &val, &lval)) {
    fwrite (var, 1, lvar, stdout);
    if (full && val) {
      putchar (' ');
      fwrite (val, 1, lval, stdout);
    }
    putchar ('\n');
    free(var);
    if (val) free(val);
    nvars++;
	}
  return (nvars==0 ? 2 : 1);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options] variable [value]\n", __progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -s          Set variable (default if value specified).\n");
	fprintf(stderr, "  -f          Set value from a file (specified as second argument, or else stdin).\n");
	fprintf(stderr, "  -g          Get variable value (default if value not specified).\n");
	fprintf(stderr, "  -l          List stored variables.\n");
	fprintf(stderr, "  -L          List stored variables and their values (may include binary values)\n");
	fprintf(stderr, "  -d          Delete stored value.\n");
	fprintf(stderr, "  -D          Delete all stored values.\n");
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	AuthenticationConnection *ac = NULL;
	int ch, set = 0, get = 0, list = 0, delete = 0, ret = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	/* At first, get a connection to the authentication agent. */
	ac = ssh_get_authentication_connection();
	if (ac == NULL) {
		fprintf(stderr,
		    "Could not open a connection to your authentication agent.\n");
		exit(2);
	}
	while ((ch = getopt(argc, argv, "hsfglLdD")) != -1) {
		switch (ch) {
		case 's':
      set = 1;
			break;
		case 'f':
      set = 2;
			break;
		case 'g':
      get = 1;
			break;
		case 'l':
      list = 1;
      break;
		case 'L':
      list = 2;
      break;
		case 'd':
			delete = 1;
			break;
		case 'D':
			delete = 2;
			break;
		default:
			usage();
			ret = 2;
			goto done;
		}
	}
	argc -= optind;
	argv += optind;

  if ((set == 1 && argc != 2) ||
      (set == 2 && (argc < 1 || argc > 2)) ||
      ((get || delete == 1) && argc != 1) ||
      ((list || delete == 2) && argc > 1) ||
      ((!!set)+(!!get)+(!!list)+(!!delete) > 1)) {
    fprintf (stderr, "%s: bad options\n", __progname);
    goto done;
  }
  if (!(set || get || list || delete)) {
    if      (argc == 1) get = 1;
    else if (argc == 2) set = 1;
    else {
      usage();
      goto done;
    }
  }

  if        (set == 2) {
    ret = set_from_file       (ac, argv[0], strlen(argv[0]), (argc >= 2 ? argv[1] : NULL));
  } else if (set) {
    ret = ssh_set_variable    (ac, argv[0], strlen(argv[0]), argv[1], strlen(argv[1]));
  } else if (get) {
    ret = print_variable      (ac, argv[0], strlen(argv[0]));
  } else if (list) {
    if (argc >= 1) {
      ret = list_variables      (ac, argv[0], strlen(argv[0]), (list==2));
    } else {
      ret = list_variables      (ac, "",      0,               (list==2));
    }
  } else if (delete) {
    if (argc >= 1) {
      ret = ssh_delete_variable (ac, argv[0], strlen(argv[0]), (delete==2));
    } else {
      ret = ssh_delete_variable (ac, "",      0,               (delete==2));
    }
  }
  
done:
	ssh_close_authentication_connection(ac);
	return (ret > 0 ? ret-1 : 10);
}
