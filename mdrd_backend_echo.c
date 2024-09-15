#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include "mdr.h"
#include "mdr_mdrd.h"
#include "util.h"

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

int
main(int argc, char **argv)
{
	int               r;
	struct mdr        m, msg;
	char              buf[32768];
	uint64_t          id;
	int               fd;
	X509             *peer_cert = NULL;
	struct sigaction  act;
	X509_STORE_CTX   *ctx;
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

	openlog("mdrd_backend_echo", LOG_PID|LOG_PERROR, LOG_USER);

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");

	if ((lookup = X509_STORE_add_lookup(store,
	    X509_LOOKUP_file())) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_load_cert_file(lookup, argv[1],
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_load_crl_file(lookup, argv[2], X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	while ((r = mdr_unpack_from_fd(&m, 0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL)
			err(1, "mdr_unpack_from_fd");

		if (mdr_namespace(&m) != MDR_NS_MDRD ||
		    mdr_id(&m) != MDR_ID_MDRD_BEREQ)
			errx(1, "invalid mdr namespace or id");

		if (mdrd_unpack_bereq(&m, &id, &fd, &msg,
		    &peer_cert) == MDR_FAIL) {
			if (errno == EAGAIN)
				warnx("mdrd_unpack_bereq: missing bytes "
				    "in payload");
			else
				warn("mdrd_unpack_bereq");
			continue;
		}

		if (peer_cert == NULL) {
			if (mdrd_pack_beresp(&m, buf, sizeof(buf), id, fd,
			    MDRD_ST_CERTFAIL,
			    MDRD_BERESP_F_CLOSE, NULL) == MDR_FAIL)
				err(1, "mdrd_pack_beresp");
		} else {
			if (!X509_STORE_CTX_init(ctx, store, peer_cert, NULL)) {
				ERR_print_errors_fp(stderr);
				exit(1);
			}

			if ((r = X509_verify_cert(ctx)) <= 0) {
				syslog(LOG_ERR, "X509_verify_cert: %s",
				    ERR_error_string(ERR_get_error(), NULL));
				exit(1);
			}
			X509_STORE_CTX_cleanup(ctx);

			X509_free(peer_cert);

			if (mdrd_pack_beresp(&m, buf, sizeof(buf), id, fd,
			    MDRD_ST_OK, MDRD_BERESP_F_MSG,
			    &msg) == MDR_FAIL)
				err(1, "mdrd_pack_beresp");
		}

		if (write(1, mdr_buf(&m), mdr_size(&m)) < mdr_size(&m))
			err(1, "writeall");
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return 0;
}
