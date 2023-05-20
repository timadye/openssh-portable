/*
 * Copyright (c) 2008, Jamie Beverly. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jamie Beverly ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Jamie Beverly OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of Jamie Beverly.
 */


#include <string.h>

#include "includes.h"
#include "config.h"

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include "ssh.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <openssl/evp.h>
#include "ssh2.h"
#include "misc.h"
#include "ssherr.h"

#include "userauth_pubkey_from_id.h"
#include "identity.h"
#include "get_command_line.h"
extern char **environ;

#define PAM_SSH_AGENT_AUTH_REQUESTv1 101

static char *
log_action(char ** action, size_t count)
{
    size_t i;
    char *buf = NULL;

    if (count == 0)
        return NULL;
   
    buf = xcalloc((count * MAX_LEN_PER_CMDLINE_ARG) + (count * 3), sizeof(*buf));
    for (i = 0; i < count; i++) {
        strcat(buf, (i > 0) ? " '" : "'");
        strncat(buf, action[i], MAX_LEN_PER_CMDLINE_ARG);
        strcat(buf, "'");
    }
    return buf;
}

void
agent_action(Buffer *buf, char ** action, size_t count)
{
    size_t i;
    buffer_init(buf);

    buffer_put_int(buf, count);

    for (i = 0; i < count; i++) {
        buffer_put_cstring(buf, action[i]);
    }
}


void
pamsshagentauth_session_id2_gen(Buffer * session_id2, const char * user,
                                const char * ruser, const char * servicename)
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;
    uint8_t cookie_len;
    char hostname[256] = { 0 };
    char pwd[1024] = { 0 };
    time_t ts;
    char ** reported_argv = NULL;
    size_t count = 0;
    char * action_logbuf = NULL;
    Buffer action_agentbuf;
    uint8_t free_logbuf = 0;
    char * retc;
    int32_t reti;

    rnd = arc4random();
    cookie_len = ((uint8_t) rnd);
    while (cookie_len < 16) { 
        cookie_len += 16;                                          /* Add 16 bytes to the size to ensure that while the length is random, the length is always reasonable; ticket #18 */
    }

    cookie = xcalloc(1,cookie_len);

    for (i = 0; i < cookie_len; i++) {
        if (i % 4 == 0) {
            rnd = arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    count = pamsshagentauth_get_command_line(&reported_argv);
    if (count > 0) { 
        free_logbuf = 1;
        action_logbuf = log_action(reported_argv, count);
        agent_action(&action_agentbuf, reported_argv, count);
        pamsshagentauth_free_command_line(reported_argv, count);
    }
    else {
        action_logbuf = "unknown on this platform";
        buffer_init(&action_agentbuf); /* stays empty, means unavailable */
    }
    
    /*
    action = getenv("SUDO_COMMAND");
    if(!action) {
        action = getenv("PAM_AUTHORIZED_ACTION");
        if(!action) {
            action = empty;
        }
    }
    */

    reti = gethostname(hostname, sizeof(hostname) - 1);
    retc = getcwd(pwd, sizeof(pwd) - 1);
    time(&ts);

    buffer_init(session_id2);

    buffer_put_int(session_id2, PAM_SSH_AGENT_AUTH_REQUESTv1);
    /* debug3("cookie: %s", tohex(cookie, cookie_len)); */
    buffer_put_string(session_id2, cookie, cookie_len);
    /* debug3("user: %s", user); */
    buffer_put_cstring(session_id2, user);
    /* debug3("ruser: %s", ruser); */
    buffer_put_cstring(session_id2, ruser);
    /* debug3("servicename: %s", servicename); */
    buffer_put_cstring(session_id2, servicename);
    /* debug3("pwd: %s", pwd); */
    if(retc)
        buffer_put_cstring(session_id2, pwd);
    else
        buffer_put_cstring(session_id2, "");
    /* debug3("action: %s", action_logbuf); */
    buffer_put_string(session_id2, sshbuf_ptr(&action_agentbuf), sshbuf_len(&action_agentbuf));
    if (free_logbuf) { 
        free(action_logbuf);
        buffer_free(&action_agentbuf);
    }
    /* debug3("hostname: %s", hostname); */
    if(reti >= 0)
        buffer_put_cstring(session_id2, hostname);
    else
        buffer_put_cstring(session_id2, "");
    /* debug3("ts: %ld", ts); */
    buffer_put_int64(session_id2, (uint64_t) ts);

    free(cookie);
    return;
}

/* 
 * Added by Jamie Beverly, ensure socket fd points to a socket owned by the user 
 * A cursory check is done, but to avoid race conditions, it is necessary 
 * to drop effective UID when connecting to the socket. 
 *
 * If the cause of error is EACCES, because we verified we would not have that 
 * problem initially, we can safely assume that somebody is attempting to find a 
 * race condition; so a more "direct" log message is generated.
 */

int
ssh_get_authentication_socket_for_uid(uid_t uid)
{
	const char *authsocket;
	int sock;
	struct sockaddr_un sunaddr;
	struct stat sock_st;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	if (!authsocket)
		return -1;

	/* Advisory only; seteuid ensures no race condition; but will only log if we see EACCES */
	if( stat(authsocket,&sock_st) == 0) {
		if(uid != 0 && sock_st.st_uid != uid) {
			fatal("uid %lu attempted to open an agent socket owned by uid %lu", (unsigned long) uid, (unsigned long) sock_st.st_uid);
			return -1;
		}
	}

	/* 
	 * Ensures that the EACCES tested for below can _only_ happen if somebody 
	 * is attempting to race the stat above to bypass authentication.
	 */
	if( (sock_st.st_mode & S_IWUSR) != S_IWUSR || (sock_st.st_mode & S_IRUSR) != S_IRUSR) {
		error("ssh-agent socket has incorrect permissions for owner");
		return -1;
	}

	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	/* close on exec */
	if (fcntl(sock, F_SETFD, 1) == -1) {
		close(sock);
		return -1;
	}

	errno = 0; 
	/* To ensure a race condition is not used to circumvent the stat
	   above, we will temporarily drop UID to the caller */
	if (seteuid(uid) == -1) {
		close(sock);
		error("seteuid(%lu) failed with error: %s", (unsigned long) uid, strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&sunaddr, sizeof sunaddr) < 0) {
		close(sock);
		sock = -1;
		if(errno == EACCES)
			fatal("MAJOR SECURITY WARNING: uid %lu made a deliberate and malicious attempt to open an agent socket owned by another user", (unsigned long) uid);
	}

	/* we now continue the regularly scheduled programming */
	if (0 != seteuid(0)) {
	fatal("setuid(0) failed with error: %s", strerror(errno));
	return -1;
	}
	return sock;
}

AuthenticationConnection *
ssh_get_authentication_connection_for_uid(uid_t uid)
{
	AuthenticationConnection *auth;
	int sock;

	sock = ssh_get_authentication_socket_for_uid(uid);

	/*
	 * Fail if we couldn't obtain a connection.  This happens if we
	 * exited due to a timeout.
	 */
	if (sock < 0)
		return NULL;

	auth = xmalloc(sizeof(*auth));
	auth->fd = sock;
	buffer_init(&auth->identities);
	auth->howmany = 0;

	return auth;
}

int
pamsshagentauth_find_authorized_keys(const char * user, const char * ruser, const char * servicename)
{
    Buffer session_id2 = { 0 };
    Identity *id;
    AuthenticationConnection *ac;
    uint8_t retval = 0;
    uid_t uid = getpwnam(ruser)->pw_uid;
    struct ssh_identitylist *idlist;
    int r;
    unsigned int i;

    OpenSSL_add_all_digests();
    pamsshagentauth_session_id2_gen(&session_id2, user, ruser, servicename);

    if ((ac = ssh_get_authentication_connection_for_uid(uid))) {
        verbose("Contacted ssh-agent of user %s (%u)", ruser, uid);
		if ((r = ssh_fetch_identitylist(ac->fd, 2,
		    &idlist)) != 0) {
			if (r != SSH_ERR_AGENT_NO_IDENTITIES)
				fprintf(stderr, "error fetching identities for "
				    "protocol %d: %s\n", 2, ssh_err(r));
		} else {
		for (i = 0; i < idlist->nkeys; i++)
        {
            if(idlist->keys[i] != NULL) {
                id = xcalloc(1, sizeof(*id));
                id->key = idlist->keys[i];
                id->filename = idlist->comments[i];
                id->ac = ac;
                if(userauth_pubkey_from_id(ruser, id, &session_id2)) {
                    retval = 1;
                }
                free(id);
                if(retval == 1)
                    break;
            }
        }
        buffer_free(&session_id2);
        ssh_free_identitylist(idlist);
        ssh_close_authentication_socket(ac->fd);
        free(ac);
        }
    }
    else {
        verbose("No ssh-agent could be contacted");
    }
    /* pamsshagentauth_xfree(session_id2); */
    EVP_cleanup();
    return retval;
}

