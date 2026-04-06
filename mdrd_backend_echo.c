/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <mdr/mdr.h>
#include <mdr/mdrd.h>
#include <mdr/util.h>
#include <mdr/xlog.h>

/*
 * A simple mdrd echo backend; it echoes back the nested mdr that's
 * contained inside the backend incoming message.
 *
 * If the client did not have a cert, it will return a CERTFAIL error.
 */

void
usage()
{
	fprintf(stderr, "Usage: mdrd_backend_echo <CA file> <CRL file>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int                     r;
	struct umdr             msg;
	char                    buf[4096];
	struct sigaction        act;
	X509_STORE_CTX         *ctx;
	X509_LOOKUP            *lookup;
	struct mdrd_besession  *sess;
	char                    hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	X509_STORE             *store;
	X509_NAME              *name;
	char                    subject[LINE_MAX];

	if (argc < 3)
		usage();

	/*
	 * We're disabling TERM/INT because we instead rely on
	 * STDIN to close to end our loop.
	 */
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1)
		return -1;

	xlog_init("mdrd_backend_echo", NULL, NULL, 1);

	if (mdr_register_builtin_specs() == MDR_FAIL)
                err(1, "mdr_register_builtin_specs");

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_init: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	if ((store = X509_STORE_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	if ((lookup = X509_STORE_add_lookup(store,
	    X509_LOOKUP_file())) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_add_lookup: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	if (!X509_load_cert_file(lookup, argv[1],
	    X509_FILETYPE_PEM)) {
		xlog(LOG_ERR, NULL, "X509_load_cert_file: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	if (!X509_load_crl_file(lookup, argv[2], X509_FILETYPE_PEM)) {
		xlog(LOG_ERR, NULL, "X509_load_crl_file: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	/*
	 * mdrd_recv will populate a message in &msg, using the underlying
	 * buf. The maximum certificate size to receive is 4096. This is used
	 * to initialize another buffer on the stack inside mdrd_recv (it
	 * avoid using the heap). Since we just echo, we accept any domain (hence
	 * the value of zero). Finally, we don't allow any extra features,
	 * and we want &sess to be populated with client session data.
	 *
	 * mdrd_recv will block, reading from STDIN and will return 0 on EOF
	 * or MDR_FAIL (-1) on error.
	 *
	 * sess contains a few useful fields, such as:
	 *   - id: the unique ID (unique per mdrd instance) of the client
	 *         session; In theory, it could wrap around as this is a
	 *         uint64_t.
	 *   - is_new: will be set to 1 when this is the first message we've
	 *             received from this client. Useful if we wish to do things
	 *             like certificate validation only once instead of every
	 *             message.
	 *   - cert: an X509 pointer for the client session's cert
	 *   - peer: a sockaddr_in6 (or sockaddr_in) with the client's address
	 *   - peer_len: the length of the peer structure
	 */
	while (mdrd_recv(&msg, buf, sizeof(buf), 4096,
	    0, MDR_FNONE, &sess) > 0) {
		if ((r = getnameinfo((struct sockaddr *)&sess->peer,
		    sess->peer_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
			xlog(LOG_ERR, NULL, "getnameinfo: %s", gai_strerror(r));

		xlog(LOG_NOTICE, NULL, "received message for id %lu, size=%lu, "
		    "from %s:%s", sess->id, umdr_size(&msg), hbuf, sbuf);

		if (sess->is_new) {
			xlog(LOG_NOTICE, NULL, "new session for id %lu",
			    sess->id);
			if (sess->cert == NULL) {
				if (mdrd_beout_error(sess,
				    MDRD_BEOUT_FCLOSE, MDR_ERR_CERTFAIL,
				    "no certificate") == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "mdr_beout_error");
					exit(1);
				}
				continue;
			}

			name = X509_get_subject_name(sess->cert);
			if (X509_NAME_oneline(name, subject,
			    sizeof(subject)) != NULL) {
				xlog(LOG_NOTICE, NULL,
				    "request from subject %s", subject);
			}

			/* Verify the cert */
			if (!X509_STORE_CTX_init(ctx, store,
			    sess->cert, NULL)) {
				xlog(LOG_ERR, NULL, "X509_STORE_CTX_init: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				exit(1);
			}

			if ((r = X509_verify_cert(ctx)) <= 0) {
				xlog(LOG_ERR, NULL, "X509_verify_cert: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				if (mdrd_beout_error(sess, MDRD_BEOUT_FCLOSE,
				    MDR_ERR_CERTFAIL, "verify failed")
				    == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "mdr_beout_error");
					exit(1);
				}
				exit(1);
			}
			X509_STORE_CTX_cleanup(ctx);
		}

		if (mdrd_beout(sess, MDRD_BEOUT_FNONE,
		    (const struct pmdr *)&msg) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdrd_beout");
			exit(1);
		}
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	mdr_registry_clear();
	return 0;
}
