#include <openssl/x509.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
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
			X509_free(peer_cert);
			if (mdrd_pack_beresp(&m, buf, sizeof(buf), id, fd,
			    MDRD_ST_OK, MDRD_BERESP_F_MSG,
			    &msg) == MDR_FAIL)
				err(1, "mdrd_pack_beresp");
		}

		if (write(1, mdr_buf(&m), mdr_size(&m)) < mdr_size(&m))
			err(1, "writeall");
	}
	return 0;
}
