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
#include "mdr.h"
#include "mdrd.h"
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
	int                  r;
	struct mdr           m, reply;
	struct mdr           msg;
	char                 buf[32768], reply_buf[32768];
	uint64_t             id;
	int                  fd;
	X509                *peer_cert = NULL;
	struct sigaction     act;
	X509_STORE_CTX      *ctx;
	X509_LOOKUP         *lookup;
	struct session      *session, *prev, *sessions = NULL;
	struct mdr_in        m_in[5];
	struct sockaddr_in6  peer;
	socklen_t            slen = sizeof(peer);
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

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

	while ((r = mdr_read_from_fd(&m, MDR_F_NONE, 0,
	    buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdr_unpack_from_fd");
			exit(1);
		}

		if (!mdr_dcv_match(&m, MDR_DOMAIN_MDRD, MDR_MASK_D)) {
			xlog(LOG_ERR, NULL, "invalid mdr domain %u",
			    mdr_domain(&m));
			exit(1);
		}

		switch (mdr_dcv(&m)) {
		case MDR_DCV_MDRD_BECLOSE:
			r = mdrd_unpack_beclose(&m, &id);
			break;
		case MDR_DCV_MDRD_BEREQ:
			r = mdrd_unpack_bereq(&m, &id, &fd,
			    (struct sockaddr *)&peer, &slen, &msg, &peer_cert);
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

		if ((r = getnameinfo((struct sockaddr *)&peer, slen,
		    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
			xlog(LOG_ERR, NULL, "getnameinfo: %s", gai_strerror(r));

		xlog(LOG_NOTICE, NULL, "received message for id %lu, size=%lu, "
		    "from %s:%s", id, mdr_size(&m), hbuf, sbuf);

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

		if (mdr_dcv(&m) == MDR_DCV_MDRD_BECLOSE) {
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
				m_in[0].type = MDR_U64;
				m_in[0].v.u64 = id;
				m_in[1].type = MDR_I32;
				m_in[1].v.i32 = fd;
				m_in[2].type = MDR_U32;
				m_in[2].v.u32 = MDRD_ST_CERTFAIL;
				m_in[3].type = MDR_U32;
				m_in[3].v.u32 = MDRD_BERESP_F_CLOSE;
				if (mdr_pack(&reply, reply_buf,
				    sizeof(reply_buf), mdr_msg_mdrd_beresp,
				    MDR_F_NONE, m_in, 4) == MDR_FAIL) {
					xlog(LOG_ERR, NULL,
					    "mdr_pack/mdrd_beresp: %d", errno);
					exit(1);
				}
				if (write(1, mdr_buf(&reply), mdr_size(&reply))
				    < mdr_size(&reply)) {
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

		m_in[0].type = MDR_U64;
		m_in[0].v.u64 = id;
		m_in[1].type = MDR_I32;
		m_in[1].v.i32 = fd;
		m_in[2].type = MDR_U32;
		m_in[2].v.u32 = MDRD_ST_OK;
		m_in[3].type = MDR_U32;
		m_in[3].v.u32 = MDRD_BERESP_F_NONE;
		m_in[4].type = MDR_M;
		m_in[4].v.m = &msg;
		if (mdr_pack(&reply, reply_buf, sizeof(reply_buf),
		    mdr_msg_mdrd_beresp_wmsg, MDR_F_NONE,
		    m_in, 5) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "mdr_pack/mdrd_beresp_wmsg");
			exit(1);
		}

		if (write(1, mdr_buf(&reply), mdr_size(&reply))
		    < mdr_size(&reply)) {
			xlog_strerror(LOG_ERR, errno, "writeall");
			exit(1);
		}
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return 0;
}
