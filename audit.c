/*
 * Copyright (c) 2004, 2005 Darren Tucker.  All rights reserved.
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

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#ifdef SSH_AUDIT_EVENTS

#include "audit.h"
#include "log.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"
#include "xmalloc.h"
#include "misc.h"
#include "servconf.h"

/*
 * Care must be taken when using this since it WILL NOT be initialized when
 * audit_connection_from() is called and MAY NOT be initialized when
 * audit_event(CONNECTION_ABANDON) is called.  Test for NULL before using.
 */
extern Authctxt *the_authctxt;
extern ServerOptions options;

/* Maybe add the audit class to struct Authmethod? */
ssh_audit_event_t
audit_classify_auth(const char *method)
{
	if (strcmp(method, "none") == 0)
		return SSH_AUTH_FAIL_NONE;
	else if (strcmp(method, "password") == 0)
		return SSH_AUTH_FAIL_PASSWD;
	else if (strcmp(method, "publickey") == 0 ||
	    strcmp(method, "rsa") == 0)
		return SSH_AUTH_FAIL_PUBKEY;
	else if (strncmp(method, "keyboard-interactive", 20) == 0 ||
	    strcmp(method, "challenge-response") == 0)
		return SSH_AUTH_FAIL_KBDINT;
	else if (strcmp(method, "hostbased") == 0 ||
	    strcmp(method, "rhosts-rsa") == 0)
		return SSH_AUTH_FAIL_HOSTBASED;
	else if (strcmp(method, "gssapi-with-mic") == 0)
		return SSH_AUTH_FAIL_GSSAPI;
	else
		return SSH_AUDIT_UNKNOWN;
}

/* helper to return supplied username */
const char *
audit_username(void)
{
	static const char unknownuser[] = "(unknown)";

	if (the_authctxt == NULL || the_authctxt->user == NULL || !the_authctxt->valid)
		return (unknownuser);
	return (the_authctxt->user);
}

const char *
audit_event_lookup(ssh_audit_event_t ev)
{
	int i;
	static struct event_lookup_struct {
		ssh_audit_event_t event;
		const char *name;
	} event_lookup[] = {
		{SSH_LOGIN_EXCEED_MAXTRIES,	"LOGIN_EXCEED_MAXTRIES"},
		{SSH_LOGIN_ROOT_DENIED,		"LOGIN_ROOT_DENIED"},
		{SSH_AUTH_SUCCESS,		"AUTH_SUCCESS"},
		{SSH_AUTH_FAIL_NONE,		"AUTH_FAIL_NONE"},
		{SSH_AUTH_FAIL_PASSWD,		"AUTH_FAIL_PASSWD"},
		{SSH_AUTH_FAIL_KBDINT,		"AUTH_FAIL_KBDINT"},
		{SSH_AUTH_FAIL_PUBKEY,		"AUTH_FAIL_PUBKEY"},
		{SSH_AUTH_FAIL_HOSTBASED,	"AUTH_FAIL_HOSTBASED"},
		{SSH_AUTH_FAIL_GSSAPI,		"AUTH_FAIL_GSSAPI"},
		{SSH_INVALID_USER,		"INVALID_USER"},
		{SSH_NOLOGIN,			"NOLOGIN"},
		{SSH_CONNECTION_CLOSE,		"CONNECTION_CLOSE"},
		{SSH_CONNECTION_ABANDON,	"CONNECTION_ABANDON"},
		{SSH_AUDIT_UNKNOWN,		"AUDIT_UNKNOWN"}
	};

	for (i = 0; event_lookup[i].event != SSH_AUDIT_UNKNOWN; i++)
		if (event_lookup[i].event == ev)
			break;
	return(event_lookup[i].name);
}

void
audit_key(int host_user, int *rv, const Key *key)
{
	char *fp;
	const char *crypto_name;

	fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_HEX);
	if (key->type == KEY_RSA1)
		crypto_name = "ssh-rsa1";
	else
		crypto_name = key_ssh_name(key);
	if (audit_keyusage(host_user, crypto_name, key_size(key), fp, *rv) == 0)
		*rv = 0;
	free(fp);
}

void
audit_unsupported(int what)
{
	PRIVSEP(audit_unsupported_body(what));
}

void
audit_kex(int ctos, char *enc, char *mac, char *comp, char *pfs)
{
	PRIVSEP(audit_kex_body(ctos, enc, mac, comp, pfs, getpid(), getuid()));
}

void
audit_session_key_free(int ctos)
{
	PRIVSEP(audit_session_key_free_body(ctos, getpid(), getuid()));
}

# ifndef CUSTOM_SSH_AUDIT_EVENTS
/*
 * Null implementations of audit functions.
 * These get used if SSH_AUDIT_EVENTS is defined but no audit module is enabled.
 */

/*
 * Called after a connection has been accepted but before any authentication
 * has been attempted.
 */
void
audit_connection_from(const char *host, int port)
{
	debug("audit connection from %s port %d euid %d", host, port,
	    (int)geteuid());
}

/*
 * Called when various events occur (see audit.h for a list of possible
 * events and what they mean).
 */
void
audit_event(ssh_audit_event_t event)
{
	debug("audit event euid %d user %s event %d (%s)", geteuid(),
	    audit_username(), event, audit_event_lookup(event));
}

/*
 * Called when a child process has called, or will soon call,
 * audit_session_open.
 */
void
audit_count_session_open(void)
{
	debug("audit count session open euid %d user %s", geteuid(),
	      audit_username());
}

/*
 * Called when a user session is started.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
void
audit_session_open(struct logininfo *li)
{
	const char *t = li->line ? li->line : "(no tty)";

	debug("audit session open euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * Called when a user session is closed.  Argument is the tty allocated to
 * the session, or NULL if no tty was allocated.
 *
 * Note that this may be called multiple times if multiple sessions are used
 * within a single connection.
 */
void
audit_session_close(struct logininfo *li)
{
	const char *t = li->line ? li->line : "(no tty)";

	debug("audit session close euid %d user %s tty name %s", geteuid(),
	    audit_username(), t);
}

/*
 * This will be called when a user runs a non-interactive command.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.  Returns a "handle" for
 * audit_end_command.
 */
int
audit_run_command(const char *command)
{
	debug("audit run command euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
	return 0;
}

/*
 * This will be called when the non-interactive command finishes.  Note that
 * it may be called multiple times for a single connection since SSH2 allows
 * multiple sessions within a single connection.  "handle" should come from
 * the corresponding audit_run_command.
 */
void
audit_end_command(int handle, const char *command)
{
	debug("audit end nopty exec  euid %d user %s command '%.200s'", geteuid(),
	    audit_username(), command);
}

/*
 * This will be called when user is successfully autherized by the RSA1/RSA/DSA key.
 *
 * Type is the key type, len is the key length(byte) and fp is the fingerprint of the key.
 */
int
audit_keyusage(int host_user, const char *type, unsigned bits, char *fp, int rv)
{
	debug("audit %s key usage euid %d user %s key type %s key length %d fingerprint %s, result %d",
		host_user ? "pubkey" : "hostbased", geteuid(), audit_username(), type, bits,
		fp, rv);
}

/*
 * This will be called when the protocol negotiation fails.
 */
void
audit_unsupported_body(int what)
{
	debug("audit unsupported protocol euid %d type %d", geteuid(), what);
}

/*
 * This will be called on succesfull protocol negotiation.
 */
void
audit_kex_body(int ctos, char *enc, char *mac, char *compress, char *pfs, pid_t pid,
	       uid_t uid)
{
	debug("audit protocol negotiation euid %d direction %d cipher %s mac %s compresion %s pfs %s from pid %ld uid %u",
		(unsigned)geteuid(), ctos, enc, mac, compress, pfs, (long)pid,
	        (unsigned)uid);
}

/*
 * This will be called on succesfull session key discard
 */
void
audit_session_key_free_body(int ctos, pid_t pid, uid_t uid)
{
	debug("audit session key discard euid %u direction %d from pid %ld uid %u",
		(unsigned)geteuid(), ctos, (long)pid, (unsigned)uid);
}

/*
 * This will be called on destroy private part of the server key
 */
void
audit_destroy_sensitive_data(const char *fp, pid_t pid, uid_t uid)
{
	debug("audit destroy sensitive data euid %d fingerprint %s from pid %ld uid %u",
		geteuid(), fp, (long)pid, (unsigned)uid);
}

/*
 * This will be called on generation of the ephemeral server key
 */
void
audit_generate_ephemeral_server_key(const char *)
{
	debug("audit create ephemeral server key euid %d fingerprint %s", geteuid(), fp);
}
# endif  /* !defined CUSTOM_SSH_AUDIT_EVENTS */
#endif /* SSH_AUDIT_EVENTS */
