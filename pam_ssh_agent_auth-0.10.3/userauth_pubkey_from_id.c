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


#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "buffer.h"
#include "log.h"
#include "compat.h"
#include "key.h"
#include "pathnames.h"
#include "misc.h"
#include "secure_filename.h"

#include "identity.h"
#include "pam_user_authorized_keys.h"

#define SSH2_MSG_USERAUTH_TRUST_REQUEST          54

/* extern u_char  *session_id2;
extern uint8_t  session_id_len;
 */

int
userauth_pubkey_from_id(const char *ruser, Identity * id, Buffer * session_id2)
{
    Buffer          b = { 0 };
    char           *pkalg = NULL;
    u_char         *pkblob = NULL, *sig = NULL;
    u_int           blen = 0;
    size_t          slen = 0;
    int             authenticated = 0;

    pkalg = (char *) key_ssh_name(id->key);

    /* construct packet to sign and test */
    buffer_init(&b);

    /* first test if this key is even allowed */
    if(! pam_user_key_allowed(ruser, id->key))
        goto user_auth_clean_exit;

    if(key_to_blob(id->key, &pkblob, &blen) == 0)
        goto user_auth_clean_exit;

    buffer_put_string(&b, sshbuf_ptr(session_id2), sshbuf_len(session_id2));
    buffer_put_char(&b, SSH2_MSG_USERAUTH_TRUST_REQUEST); 
    buffer_put_cstring(&b, ruser);
    buffer_put_cstring(&b, "pam_ssh_agent_auth");
    buffer_put_cstring(&b, "publickey");
    buffer_put_char(&b, 1);
    buffer_put_cstring(&b, pkalg);
    buffer_put_string(&b, pkblob, blen);

    if(ssh_agent_sign(id->ac->fd, id->key, &sig, &slen, buffer_ptr(&b), buffer_len(&b), NULL, 0) != 0)
        goto user_auth_clean_exit;

    /* test for correct signature */
    if(key_verify(id->key, sig, slen, buffer_ptr(&b), buffer_len(&b)) == 1)
        authenticated = 1;

  user_auth_clean_exit:
    /* if(&b != NULL) */
    buffer_free(&b);
    if(sig != NULL)
        free(sig);
    if(pkblob != NULL)
        free(pkblob);
    CRYPTO_cleanup_all_ex_data();
    return authenticated;
}
