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
	struct umdr          m_in, msg;
	struct pmdr          reply;
	struct pmdr_vec      pv[5];
	char                 m_in_buf[4096], reply_buf[4096], msg_buf[4096];
	uint64_t             id;
	int                  fd;
	X509                *peer_cert = NULL;
	struct sigaction     act;
	X509_STORE_CTX      *ctx;
	X509_LOOKUP         *lookup;
	struct session      *session, *prev, *sessions = NULL;
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

	pmdr_init(&reply, reply_buf, sizeof(reply_buf), MDR_FNONE);

	while ((r = mdr_buf_from_fd(0, m_in_buf, sizeof(m_in_buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdr_buf_from_fd");
			continue;
		}

		if (umdr_init(&m_in, m_in_buf, sizeof(m_in_buf), MDR_FNONE)
		    == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "umdr_init");
			continue;
		}

		if (!umdr_dcv_match(&m_in, MDR_DOMAIN_MDRD, MDR_MASK_D)) {
			xlog(LOG_ERR, NULL, "invalid mdr domain %u",
			    umdr_domain(&m_in));
			continue;
		}

		switch (umdr_dcv(&m_in)) {
		case MDR_DCV_MDRD_BECLOSE:
			r = mdrd_unpack_beclose(&m_in, &id);
			break;
		case MDR_DCV_MDRD_BEREQ:
			umdr_init0(&msg, msg_buf, sizeof(msg_buf), MDR_FNONE);
			r = mdrd_unpack_bereq(&m_in, &id, &fd,
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
		    "from %s:%s", id, umdr_size(&m_in), hbuf, sbuf);

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

		if (umdr_dcv(&m_in) == MDR_DCV_MDRD_BECLOSE) {
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
				pv[0].type = MDR_U64;
				pv[0].v.u64 = id;
				pv[1].type = MDR_I32;
				pv[1].v.i32 = fd;
				pv[2].type = MDR_U32;
				pv[2].v.u32 = MDRD_BERESP_CERTFAIL;
				pv[3].type = MDR_U32;
				pv[3].v.u32 = MDRD_BERESP_FCLOSE;
				if (pmdr_pack(&reply, mdr_msg_mdrd_beresp,
				    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
					xlog(LOG_ERR, NULL,
					    "mdr_pack/mdrd_beresp: %d", errno);
					exit(1);
				}
				if (write(1, pmdr_buf(&reply),
				    pmdr_size(&reply)) < pmdr_size(&reply)) {
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

		pv[0].type = MDR_U64;
		pv[0].v.u64 = id;
		pv[1].type = MDR_I32;
		pv[1].v.i32 = fd;
		pv[2].type = MDR_U32;
		pv[2].v.u32 = MDRD_BERESP_OK;
		pv[3].type = MDR_U32;
		pv[3].v.u32 = MDRD_BERESP_FNONE;
		pv[4].type = MDR_M;
		pv[4].v.umdr = &msg;
		if (pmdr_pack(&reply, mdr_msg_mdrd_beresp_wmsg, pv,
		    PMDRVECLEN(pv)) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "mdr_pack/mdrd_beresp_wmsg");
			exit(1);
		}

		if (write(1, pmdr_buf(&reply), pmdr_size(&reply))
		    < pmdr_size(&reply)) {
			xlog_strerror(LOG_ERR, errno, "writeall");
			exit(1);
		}
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	mdr_registry_clear();
	return 0;
}
