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
#include <string.h>
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

X509_STORE_CTX      *ctx;
X509_STORE          *store;

void
usage()
{
	fprintf(stderr, "Usage: mdrd_backend_echo <CA file> <CRL file>\n");
	exit(1);
}

void
process_messages()
{
	int                  r;
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	X509_NAME           *name;
	char                 subject[LINE_MAX];
	struct mdrd_recvhdl  mrh;
	char                 buf[mdr_spec_base_sz(mdr_msg_mdrd_bein,
	    4096     /* Max payload size */
	    + 4096   /* Max cert size */
	    + sizeof(struct sockaddr_in6))];

	/*
	 * mdrd_recv() will populate mrh->msg and mrh->session. It uses
	 * the supplied buffer to store the data read from STDIN. The buffer
	 * will be reused on the next call of mdrd_recv(), which means
	 * mrh->msg will no longer be valid. It should be copied if we wish
	 * to access it later, or if mrh goes out of scope.
	 *
	 * mrh->session will also be reset to another session on the next
	 * call to mdrd_recv().
	 *
	 * The supplied buffer should be large enough to hold the maximum
	 * payload size we're willing to accept, plus the maximum X509 cert
	 * size we allow, plus the BEIN headers. See above for a helper to
	 * allocate.
	 *
	 * mdrd_recv() will block on STDIN until either:
	 * 
	 *   - the timeout (ms) is reached, in which case MDR_FAIL will be
	 *     returned and errno will be set to ETIMEDOUT
	 *   - STDIN is closed, which will cause mdrd_recv() to return 0
	 *   - a complete message is available; the return value will be
	 *     the message size.
	 *
	 * mrh->session contains a few useful fields, such as:
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
	bzero(&mrh, sizeof(mrh));
	mrh.buf = buf;
	mrh.bufsz = sizeof(buf);
	for (;;) {
		if ((r = mdrd_recv(&mrh, 5000)) == MDR_FAIL) {
			if (errno == ETIMEDOUT) {
				xlog(LOG_NOTICE, NULL, "no message received, "
				    "performing routine tasks...");
				continue;
			}

			/* Any other error */
			err(1, "mdrd_recv");
		}

		if (r == 0) {
			xlog(LOG_NOTICE, NULL, "mdrd closed stdin, exiting");
			break;
		}

		if ((r = getnameinfo((struct sockaddr *)&mrh.session->peer,
		    mrh.session->peer_len, hbuf, sizeof(hbuf), sbuf,
		    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
			xlog(LOG_ERR, NULL, "getnameinfo: %s", gai_strerror(r));

		xlog(LOG_NOTICE, NULL, "received message for id %lu, size=%lu, "
		    "from %s:%s", mrh.session->id, umdr_size(mrh.msg),
		    hbuf, sbuf);

		if (mrh.session->is_new) {
			xlog(LOG_NOTICE, NULL, "new session for id %lu",
			    mrh.session->id);
			if (mrh.session->cert == NULL) {
				if (mdrd_beout_error(mrh.session,
				    MDRD_BEOUT_FCLOSE, MDR_ERR_CERTFAIL,
				    "no certificate") == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "mdr_beout_error");
					exit(1);
				}
				continue;
			}

			name = X509_get_subject_name(mrh.session->cert);
			if (X509_NAME_oneline(name, subject,
			    sizeof(subject)) != NULL) {
				xlog(LOG_NOTICE, NULL,
				    "request from subject %s", subject);
			}

			/* Verify the cert */
			if (!X509_STORE_CTX_init(ctx, store,
			    mrh.session->cert, NULL)) {
				xlog(LOG_ERR, NULL, "X509_STORE_CTX_init: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				exit(1);
			}

			if ((r = X509_verify_cert(ctx)) <= 0) {
				xlog(LOG_ERR, NULL, "X509_verify_cert: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				if (mdrd_beout_error(mrh.session,
				    MDRD_BEOUT_FCLOSE, MDR_ERR_CERTFAIL,
				    "verify failed") == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "mdr_beout_error");
					exit(1);
				}
				exit(1);
			}
			X509_STORE_CTX_cleanup(ctx);
		}

		if (mdrd_beout(mrh.session, MDRD_BEOUT_FNONE,
		    (const struct pmdr *)mrh.msg) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdrd_beout");
			exit(1);
		}
	}

	r = mdrd_purge_sessions(NULL, 0);
	xlog(LOG_NOTICE, NULL, "ending recv loop, puring %d sessions", r);
}

int
main(int argc, char **argv)
{
	struct sigaction  act;
	X509_LOOKUP      *lookup;

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

	process_messages();
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	mdr_registry_clear();
	return 0;
}
