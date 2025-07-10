#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "mdr.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "xlog.h"

/*
 * A simple mdrd echo backend; it echoes back the nested mdr that's
 * contained inside the bereq (backend request).
 *
 * If the client did not have a cert, it will return a CERTFAIL error.
 */

X509_STORE     *store;
X509_STORE_CTX *ctx;

void
usage()
{
	fprintf(stderr, "Usage: mdrd_backend_echo <CA file> <CRL file>\n");
	exit(1);
}

struct session
{
	uint64_t        id;
	X509           *cert;
	struct session *next;
};

int
main(int argc, char **argv)
{
	int               r;
	struct mdr        m, msg;
	char              buf[32768], msg_buf[16384];
	uint64_t          id;
	int               fd;
	X509             *peer_cert = NULL;
	struct sigaction  act;
	X509_STORE_CTX   *ctx;
	X509_LOOKUP      *lookup;
	struct session   *session, *prev, *sessions = NULL;

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

	while ((r = mdr_unpack_from_fd(&m, MDR_F_NONE,
	    0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdr_unpack_from_fd");
			exit(1);
		}

		if (mdr_domain(&m) != MDR_NS_MDRD) {
			xlog(LOG_ERR, NULL, "invalid mdr domain %u",
			    mdr_domain(&m));
			exit(1);
		}

		switch (mdr_code(&m)) {
		case MDR_NAME_MDRD_BECLOSE:
			r = mdrd_unpack_beclose(&m, &id);
			break;
		case MDR_NAME_MDRD_BEREQ:
			r = mdrd_unpack_bereq(&m, &id, &fd, &msg, msg_buf,
			    sizeof(msg_buf), &peer_cert);
			break;
		default:
			xlog(LOG_ERR, NULL, "invalid mdr id %u", id);
			continue;
		}

		if (r == MDR_FAIL) {
			if (errno != EAGAIN)
				xlog_strerror(LOG_ERR, errno,
				    "error unpacking MDR");
			continue;
		}

		xlog(LOG_NOTICE, NULL, "received message for id %lu, size=%lu",
		    id, mdr_size(&m));

		/* Lookup which session this message is for */
		for (session = sessions, prev = NULL;
		    session != NULL;
		    prev = session, session = session->next) {
			if (session->id == id) {
				xlog(LOG_NOTICE, NULL,
				    "found session for id %lu", id);
				break;
			}
		}

		if (mdr_code(&m) == MDR_NAME_MDRD_BECLOSE) {
			/*
			 * Session was not found but we're cleaning up, so
			 * nothing to do.
			 */
			if (session == NULL)
				continue;

			xlog(LOG_NOTICE, NULL,
			    "cleaning up session for id %lu", id);
			if (prev != NULL)
				prev->next = session->next;
			X509_free(session->cert);
			free(session);
			/*
			 * No response is expected on BECLOSE.
			 */
			continue;
		}

		/*
		 * This is a new session; save the cert.
		 */
		if (session == NULL) {
			xlog(LOG_NOTICE, NULL, "new session for id %lu", id);
			if (peer_cert == NULL) {
				if (mdrd_pack_beresp(&m, buf, sizeof(buf), id,
				    fd, MDRD_ST_CERTFAIL,
				    MDRD_BERESP_F_CLOSE) == MDR_FAIL) {
					xlog(LOG_ERR, NULL,
					    "mdrd_pack_beresp: %d", errno);
					exit(1);
				}
				if (write(1, mdr_buf(&m), mdr_size(&m))
				    < mdr_size(&m)) {
					xlog_strerror(LOG_ERR, errno, "malloc");
					exit(1);
				}
				continue;
			}

			/* Verify the cert */
			if (!X509_STORE_CTX_init(ctx, store, peer_cert, NULL)) {
				xlog(LOG_ERR, NULL, "X509_STORE_CTX_init: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				exit(1);
			}
			if ((r = X509_verify_cert(ctx)) <= 0) {
				xlog(LOG_ERR, NULL, "X509_verify_cert: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				exit(1);
			}
			X509_STORE_CTX_cleanup(ctx);

			/*
			 * Keep track of our session in our list.
			 */
			if ((session = malloc(sizeof(struct session))) == NULL) {
				xlog_strerror(LOG_ERR, errno, "malloc");
				exit(1);
			}
			session->id = id;
			session->cert = peer_cert;
			session->next = NULL;
			if (sessions != NULL) {
				session->next = sessions;
			}
			sessions = session;
		}

		if (mdrd_pack_beresp_wmsg(&m, buf, sizeof(buf), id,
		    fd, MDRD_ST_OK, MDRD_BERESP_F_NONE, &msg) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdrd_pack_beresp");
			exit(1);
		}

		if (write(1, mdr_buf(&m), mdr_size(&m)) < mdr_size(&m)) {
			xlog_strerror(LOG_ERR, errno, "writeall");
			exit(1);
		}
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return 0;
}
