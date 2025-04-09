#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "counters.h"
#include "flatconf.h"
#include "mdr.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "tlsev.h"
#include "xlog.h"

const char *program = "mdrd";
X509_STORE *store = NULL;
EVP_PKEY   *priv_key = NULL;
X509       *ca_crt = NULL;

struct spawnproc      sproc;
struct tlsev_listener listener;
struct tlsev_fd_cb    backend_reader;
int                   backend_wfd;
volatile sig_atomic_t shutdown_triggered = 0;

int  foreground = 0;
int  debug = 0;
int  ssl_data_idx;
char config_file_path[PATH_MAX] = "/etc/mdrd.conf";

uint32_t *allowed_mdr_namespaces = NULL;
int       allowed_mdr_namespaces_count = 0;

extern char *optarg;
extern int   optind, opterr, optopt;

struct {
	char *uid;
	char *gid;
	int   enable_coredumps;

	char  counters_sock[PATH_MAX];
	char  pid_file[PATH_MAX];
	char  ca_file[PATH_MAX];
	char  crl_file[PATH_MAX];
	char  key_file[PATH_MAX];

	uint64_t port;
	uint64_t listen_backlog;
	uint64_t prefork;
	uint64_t max_clients;
	uint64_t max_conn_per_ip;
	uint64_t socket_timeout_min;
	uint64_t socket_timeout_max;
	uint64_t max_payload_size;
	uint64_t max_cert_size;
	int      use_rcv_lowat;
	int      so_debug;
	uint64_t rcvbuf;
	uint64_t sndbuf;

	uint64_t **allowed_mdr_namespaces;

	char **backend_argv;
	char  *backend_uid;
	char  *backend_gid;
	char   backend_promises[LINE_MAX];
	char **backend_unveils;
} mdrd_conf = {
	"_mdrd",
	"_mdrd",
	0,
	"/var/run/mdrd_counters.sock",
	"/var/run/mdrd.pid",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"ca/private/overnet_key.pem",
	9790,
	128,
	4,
	1000,
	100,
	2,
	10,
	16384,
	4096,
	0,
	0,
	0,
	0,
	NULL,
	NULL,
	"_mdrd",
	"_mdrd",
	"stdio rpath flock",
	NULL
};

struct flatconf flatconf_vars[] = {
	{
		"uid",
		FLATCONF_ALLOCSTRING,
		&mdrd_conf.uid,
		0
	},
	{
		"gid",
		FLATCONF_ALLOCSTRING,
		&mdrd_conf.gid,
		0
	},
	{
		"enable_coredumps",
		FLATCONF_BOOLINT,
		&mdrd_conf.enable_coredumps,
		sizeof(mdrd_conf.enable_coredumps)
	},
	{
		"pid_file",
		FLATCONF_STRING,
		mdrd_conf.pid_file,
		sizeof(mdrd_conf.pid_file)
	},
	{
		"counters_sock",
		FLATCONF_STRING,
		mdrd_conf.counters_sock,
		sizeof(mdrd_conf.counters_sock)
	},
	{
		"ca_file",
		FLATCONF_STRING,
		mdrd_conf.ca_file,
		sizeof(mdrd_conf.ca_file)
	},
	{
		"crl_file",
		FLATCONF_STRING,
		mdrd_conf.crl_file,
		sizeof(mdrd_conf.crl_file)
	},
	{
		"key_file",
		FLATCONF_STRING,
		mdrd_conf.key_file,
		sizeof(mdrd_conf.key_file)
	},
	{
		"port",
		FLATCONF_ULONG,
		&mdrd_conf.port,
		sizeof(mdrd_conf.port)
	},
	{
		"listen_backlog",
		FLATCONF_ULONG,
		&mdrd_conf.listen_backlog,
		sizeof(mdrd_conf.listen_backlog)
	},
	{
		"prefork",
		FLATCONF_ULONG,
		&mdrd_conf.prefork,
		sizeof(mdrd_conf.prefork)
	},
	{
		"max_clients",
		FLATCONF_ULONG,
		&mdrd_conf.max_clients,
		sizeof(mdrd_conf.max_clients)
	},
	{
		"max_conn_per_ip",
		FLATCONF_ULONG,
		&mdrd_conf.max_conn_per_ip,
		sizeof(mdrd_conf.max_conn_per_ip)
	},
	{
		"socket_timeout_min",
		FLATCONF_ULONG,
		&mdrd_conf.socket_timeout_min,
		sizeof(mdrd_conf.socket_timeout_min)
	},
	{
		"socket_timeout_max",
		FLATCONF_ULONG,
		&mdrd_conf.socket_timeout_max,
		sizeof(mdrd_conf.socket_timeout_max)
	},
	{
		"max_payload_size",
		FLATCONF_ULONG,
		&mdrd_conf.max_payload_size,
		sizeof(mdrd_conf.max_payload_size)
	},
	{
		"max_cert_size",
		FLATCONF_ULONG,
		&mdrd_conf.max_cert_size,
		sizeof(mdrd_conf.max_cert_size)
	},
	{
		"use_rcv_lowat",
		FLATCONF_BOOLINT,
		&mdrd_conf.use_rcv_lowat,
		sizeof(mdrd_conf.use_rcv_lowat)
	},
	{
		"so_debug",
		FLATCONF_BOOLINT,
		&mdrd_conf.so_debug,
		sizeof(mdrd_conf.so_debug)
	},
	{
		"rcvbuf",
		FLATCONF_ULONG,
		&mdrd_conf.rcvbuf,
		sizeof(mdrd_conf.rcvbuf)
	},
	{
		"sndbuf",
		FLATCONF_ULONG,
		&mdrd_conf.sndbuf,
		sizeof(mdrd_conf.sndbuf)
	},
	{
		"allowed_mdr_namespaces",
		FLATCONF_ALLOCULONGLIST,
		&mdrd_conf.allowed_mdr_namespaces,
		0
	},
	{
		"backend_argv",
		FLATCONF_ALLOCSTRINGLIST,
		&mdrd_conf.backend_argv,
		0
	},
	{
		"backend_uid",
		FLATCONF_ALLOCSTRING,
		&mdrd_conf.backend_uid,
		0
	},
	{
		"backend_gid",
		FLATCONF_ALLOCSTRING,
		&mdrd_conf.backend_gid,
		0
	},
	{
		"backend_promises",
		FLATCONF_STRING,
		&mdrd_conf.backend_promises,
		sizeof(mdrd_conf.backend_promises)
	},
	{
		"backend_unveils",
		FLATCONF_ALLOCSTRINGLIST,
		&mdrd_conf.backend_unveils,
		0
	},
	FLATCONF_LAST
};

static int
pack_bereq(struct mdr *m, uint64_t id, int fd, struct mdr *msg, X509 *peer_cert)
{
	size_t                    cert_len;
	unsigned char            *cert_buf;

	cert_len = i2d_X509(peer_cert, NULL);
	if (cert_len < 0) {
		xlog(LOG_ERR, NULL, "%s: i2d_X509() < 0", __func__);
		return -1;
	}

	if (cert_len > mdrd_conf.max_cert_size) {
		xlog(LOG_ERR, NULL, "%s: X509 length above limit: "
		    "%lu > %lu", __func__, cert_len, mdrd_conf.max_cert_size);
	}

	if (mdr_pack_hdr(m, NULL, 4096, MDR_F_NONE, MDR_NS_MDRD,
	    MDR_ID_MDRD_BEREQ, 0) == MDR_FAIL ||
	    mdr_pack_uint64(m, id) == MDR_FAIL ||
	    mdr_pack_int32(m, fd) == MDR_FAIL ||
	    mdr_pack_mdr(m, msg) == MDR_FAIL ||
	    mdr_pack_space(m, (char **)&cert_buf, cert_len) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack", __func__);
		return -1;
	}
	i2d_X509(peer_cert, &cert_buf);

	return 0;
}

/*
 *  The verification callback can be used to customise the operation of
 *  certificate verification, for instance by overriding error conditions or
 *  logging errors for debugging purposes.
 *
 *  The ok parameter to the callback indicates the value the callback should
 *  return to retain the default behaviour. If it is zero then an error
 *  condition is indicated. If it is 1 then no error occurred. If the flag
 *  X509_V_FLAG_NOTIFY_POLICY is set then ok is set to 2 to indicate the policy
 *  checking is complete.
 */
int
verify_callback_daemon(int ok, X509_STORE_CTX *ctx)
{
	int           e;
	SSL          *ssl;
	X509         *err_cert;
	struct tlsev *t;
	char          name[256];
	char          hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	ssl = X509_STORE_CTX_get_ex_data(ctx,
	    SSL_get_ex_data_X509_STORE_CTX_idx());
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	t = SSL_get_ex_data(ssl, ssl_data_idx);

	if (getnameinfo((struct sockaddr *)&t->peer_addr,
	    sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		hbuf[0] = '?';
		hbuf[1] = '\0';
		sbuf[0] = '?';
		sbuf[1] = '\0';
	}

	if (!ok) {
		X509_NAME_oneline(X509_get_subject_name(err_cert),
		    name, sizeof(name));
		e = X509_STORE_CTX_get_error(ctx);
		xlog(LOG_NOTICE, NULL, "verify error for %s (%s:%s): %s\n",
		    name, hbuf, sbuf, X509_verify_cert_error_string(e));
	}
	return ok;
}

void
usage()
{
	printf("Usage: %s [options] <command>\n", program);
	printf("\t-h            Prints this help\n");
	printf("\t-d            Do not fork and print errors to STDERR\n");
	printf("\t-f            Do not fork\n");
	printf("\t-c <conf>     Specify alternate configuration path\n");
}

void
handle_signals(int sig)
{
	xlog(LOG_NOTICE, NULL, "signal received: %d", sig);
	shutdown_triggered = 1;
	tlsev_shutdown(&listener);
}

struct client_cb_data {
	size_t      len;
	char       *buf;
	size_t      buf_sz;
	struct mdr  msg;
	int         send_cert;
};

void
client_close_cb(struct tlsev *t, void *data)
{
	struct mdr bemsg;
	char       buf[mdr_hdr_size(0) + sizeof(uint64_t)];

	if (mdr_pack_hdr(&bemsg, buf, sizeof(buf), MDR_F_NONE, MDR_NS_MDRD,
	    MDR_ID_MDRD_BECLOSE, 0) == MDR_FAIL ||
	    mdr_pack_uint64(&bemsg, tlsev_id(t)) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack_hdr", __func__);
	} else {
		if (writeall(backend_wfd, mdr_buf(&bemsg),
		    mdr_size(&bemsg)) == -1)
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
	}

	struct client_cb_data *cb_data = (struct client_cb_data *)data;
	if (cb_data->buf != NULL)
		free(cb_data->buf);
	free(cb_data);
}

int
client_msg_in_cb(struct tlsev *t, const char *buf, size_t n, void **data)
{
	struct client_cb_data *cb_data = (struct client_cb_data *)(*data);
	void                     *tmp;
	struct mdr                bemsg;
	int                       status, i;

	if (cb_data == NULL) {
		*data = malloc(sizeof(struct client_cb_data));
		if (*data == NULL) {
			xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
			return -1;
		}
		bzero(*data, sizeof(struct client_cb_data));
		cb_data = (struct client_cb_data *)(*data);
		cb_data->send_cert = 1;
		cb_data->buf = malloc(n);
		if (cb_data->buf == NULL) {
			free(cb_data);
			cb_data = NULL;
			xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
			return -1;
		}
		cb_data->buf_sz = n;
	} else if (cb_data->len + n > cb_data->buf_sz) {
		tmp = realloc(cb_data->buf, cb_data->len + n);
		if (tmp == NULL) {
			xlog_strerror(LOG_ERR, errno, "%s: realloc", __func__);
			client_close_cb(t, *data);
			return -1;
		}
		cb_data->buf = tmp;
		cb_data->buf_sz = cb_data->len + n;
	}

	memcpy(cb_data->buf + cb_data->len, buf, n);
	cb_data->len += n;

	if (mdr_unpack_all(&cb_data->msg, MDR_F_NONE, cb_data->buf,
	    cb_data->len, mdrd_conf.max_payload_size) == MDR_FAIL) {
		if (errno == EAGAIN)
			return 0;
		xlog_strerror(LOG_ERR, errno, "%s: mdr_unpack_all", __func__);
		return -1;
	}

	counters_incr(COUNTER_MESSAGES_IN);

	for (i = 0; mdrd_conf.allowed_mdr_namespaces &&
	    mdrd_conf.allowed_mdr_namespaces[i] != NULL; i++) {
		if (mdr_namespace(&cb_data->msg) ==
		    *mdrd_conf.allowed_mdr_namespaces[i])
			break;
	}
	if (mdrd_conf.allowed_mdr_namespaces[i] == NULL) {
		counters_incr(COUNTER_MESSAGES_IN_DENIED);
		xlog_strerror(LOG_ERR, errno,
		    "%s: namespace not allowed", __func__);
		return -1;
	}

	if ((status = pack_bereq(&bemsg, tlsev_id(t), tlsev_fd(t),
	    &cb_data->msg,
	    (cb_data->send_cert) ? tlsev_peer_cert(t) : NULL)) == 0) {
		/*
		 * We only sent the cert the first time; backend should
		 * remember it.
		 */
		cb_data->send_cert = 0;

		if ((status = writeall(backend_wfd, mdr_buf(&bemsg),
		    mdr_size(&bemsg))) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		}
	}

	mdr_free(&bemsg);

	memmove(cb_data->buf, cb_data->buf + mdr_size(&cb_data->msg),
	    cb_data->len - mdr_size(&cb_data->msg));
	cb_data->len -= mdr_size(&cb_data->msg);
	return status;
}

int
backend_msg_in_cb(int fd)
{
	struct mdr    reply, msg;
	char          reply_buf[mdrd_conf.max_payload_size + 4096];
	char          msg_buf[mdrd_conf.max_payload_size];
	struct tlsev *t;
	uint64_t      id;
	int           tlsfd, r;
	uint32_t      resp_status, resp_flags;

	if ((r = mdr_unpack_from_fd(&reply, MDR_F_NONE, fd,
	    reply_buf, sizeof(reply_buf))) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: mdr_unpack_from_fd", __func__);
		goto fail;
	}

	if (r == 0) {
		xlog(LOG_ERR, NULL,
		    "%s: mdr_unpack_from_fd: EOF from backend", __func__);
		goto fail;
	}

	if (mdr_id(&reply) != MDR_ID_MDRD_BERESP) {
		xlog(LOG_ERR, NULL,
		    "%s: unexpected message ID from backend", __func__);
		goto fail;
	}

	if (mdr_unpack_uint64(&reply, &id) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: failed to unpack message client connection ID",
		    __func__);
		goto fail;
	}

	if (mdr_unpack_int32(&reply, &tlsfd) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: failed to unpack client file descriptor", __func__);
		goto fail;
	}

	if (mdr_unpack_uint32(&reply, &resp_status) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: failed to unpack response status from backend",
		    __func__);
		goto fail;
	}

	if (mdr_unpack_uint32(&reply, &resp_flags) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: failed to unpack response flags from backend",
		    __func__);
		goto fail;
	}

	if ((t = tlsev_get(&listener, tlsfd)) == NULL) {
		xlog(LOG_ERR, NULL,
		    "%s: tlsev_get on fd %d not found", __func__, fd);
		return 1;
	}

	if (tlsev_id(t) != id) {
		xlog(LOG_ERR, NULL,
		    "%s: received reply from backend for a client that is "
		    " gone on fd %d", __func__, tlsfd);
		return 1;
	}

	switch (resp_status) {
	case MDRD_ST_OK:
		if (resp_flags & MDRD_BERESP_F_MSG) {
			if (mdr_unpack_mdr_ref(&reply, &msg) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: reply from backend is invalid",
				    __func__);
				goto fail;
			}
		}
		break;
	case MDRD_ST_DENIED:
		if (mdrd_pack_error(&msg, msg_buf, sizeof(msg_buf),
		    resp_status, "access denied") == MDR_FAIL) {
			xlog(LOG_ERR, NULL, "%s: failed to pack error for "
			    "client after resp_status %u",
			    __func__, resp_status);
			goto fail;
		}
		break;
	case MDRD_ST_CERTFAIL:
		if (mdrd_pack_error(&msg, msg_buf, sizeof(msg_buf),
		    resp_status, "certificate validation failed") == MDR_FAIL) {
			xlog(LOG_ERR, NULL, "%s: failed to pack error for "
			    "client after resp_status %u",
			    __func__, resp_status);
			goto fail;
		}
		break;
	default:
		xlog(LOG_ERR, NULL, "%s: unknown mdr status from backend: %u",
		    __func__, resp_status);
		goto fail;
	}

	if ((r = tlsev_reply(t, mdr_buf(&msg), mdr_size(&msg))) <= 0 ||
	    resp_flags & MDRD_BERESP_F_CLOSE)
		tlsev_drain(t);

	counters_incr(COUNTER_MESSAGES_OUT);

	/*
	 * TODO: backend could overflow us here. We should cap how many
	 * bytes pending we have and create a message to tell our backend
	 * to stop pause message for this client.
	 * This only matters in a "streaming" situation where we don't
	 * have 1:1 requests/replies. We'll need a message serial number
	 * to properly inform the backend where to resme.
	 * The code above assumes we get a "reply" from the backend,
	 * always, so it's not yet able to support this kind of streaming.
	 */

	return 1;
fail:
	tlsev_shutdown(&listener);
	shutdown_triggered = 1;
	return 0;
}

void
load_keys()
{
	FILE        *f;
	X509_LOOKUP *lookup;

	if ((f = fopen(mdrd_conf.key_file, "r")) == NULL)
		err(1, "fopen");
	if ((priv_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if ((f = fopen(mdrd_conf.ca_file, "r")) == NULL)
		err(1, "fopen");
	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_cert_file(lookup, mdrd_conf.ca_file,
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_crl_file(lookup, mdrd_conf.crl_file,
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/*
	 * We're not calling X509_LOOKUP_free() as this causes a segfault
	 * if we try reusing X509_LOOKUP_file().
	 */
}

void
cleanup()
{
	flatconf_free(flatconf_vars);
	if (ca_crt != NULL) {
		X509_free(ca_crt);
		ca_crt = NULL;
	}
	if (priv_key != NULL) {
		EVP_PKEY_free(priv_key);
		priv_key = NULL;
	}
}

int
run(SSL_CTX *ctx, int *lsock, size_t lsock_len)
{
	int status;

	if (tlsev_init(&listener, ctx, lsock, lsock_len,
	    mdrd_conf.socket_timeout_min,
	    mdrd_conf.socket_timeout_max,
	    mdrd_conf.max_clients,
	    mdrd_conf.max_conn_per_ip,
	    mdrd_conf.use_rcv_lowat,
	    ssl_data_idx, &client_msg_in_cb, &client_close_cb) == -1) {
		xlog_strerror(LOG_ERR, errno, "tlsev_init");
		return 1;
	}
	if (tlsev_add_fd_cb(&listener, &backend_reader)) {
		xlog_strerror(LOG_ERR, errno, "tlsev_add_fd_cb");
		return 1;
	}
	status = tlsev_run(&listener);
	SSL_CTX_free(ctx);
	tlsev_destroy(&listener);
	cleanup();
	return status;
}

int
get_listen_socket(int domain, int type, unsigned short port)
{
	int                 fd;
	struct sockaddr_in6 sa6;
	struct sockaddr_in  sa;
	int                 one = 1;
	int                 bufsz;
#ifdef __linux__
	int                 defer_accept_seconds = 5;
#endif

	if ((fd = socket(domain, type, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		xlog_strerror(LOG_ERR, errno, "setsockopt");
		return -1;
	}

#ifdef __linux__
	if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
	    &defer_accept_seconds, sizeof(defer_accept_seconds)) == -1) {
		xlog_strerror(LOG_ERR, errno, "setsockopt");
		return -1;
	}
#endif

#ifdef __OpenBSD__
	if (mdrd_conf.so_debug &&
	    setsockopt(fd, SOL_SOCKET, SO_DEBUG, &one, sizeof(one)) == -1) {
		xlog_strerror(LOG_ERR, errno, "setsockopt");
		return -1;
	}
#endif

	if (mdrd_conf.rcvbuf > 0) {
		bufsz = (mdrd_conf.rcvbuf >= INT_MAX) ? 0 : mdrd_conf.rcvbuf;
#ifdef __OpenBSD__
		if (bufsz > 0 &&
		    mdrd_conf.use_rcv_lowat &&
		    bufsz < (2<<14)) {
			/*
			 * OpenBSD currently has an issue where a socket
			 * with SO_RCVLOWAT and a small window may stall:
			 *   https://marc.info/?l=openbsd-bugs&m=173368617609288&w=2
			 * Until this is resolved, make sure our buffer can
			 * hold at least a full TLS record and enough extra to
			 * advertise a non-zero window when the scaling factor
			 * is 14 (max).
			 */
			bufsz = 2<<14;
		}
#endif
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
		    &bufsz, sizeof(bufsz)) == -1) {
			xlog_strerror(LOG_ERR, errno, "setsockopt");
			return -1;
		}
	}
	if (mdrd_conf.sndbuf > 0) {
		bufsz = (mdrd_conf.sndbuf >= INT_MAX) ? 0 : mdrd_conf.sndbuf;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
		    &bufsz, sizeof(bufsz)) == -1) {
			xlog_strerror(LOG_ERR, errno, "setsockopt");
			return -1;
		}
	}

	if (domain == AF_INET6) {
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = domain;
		memcpy(&sa6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
		sa6.sin6_port = htons(port);
		if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) == -1) {
			xlog_strerror(LOG_ERR, errno, "bind");
			return -1;
		}
	} else {
		bzero(&sa, sizeof(sa));
		sa.sin_family = domain;
		sa.sin_port = htons(port);
		if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
			xlog_strerror(LOG_ERR, errno, "bind");
			return -1;
		}
	}

	if (listen(fd, mdrd_conf.listen_backlog) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		return -1;
	}

	return fd;
}

void
counters_sig_handler(int sig)
{
	if (sig == SIGCHLD) {
		while (waitpid(-1, NULL, WNOHANG) > 0);
		return;
	}
	shutdown_triggered = 1;
	exit(0);
}

int
counter_reader()
{
	int                lsock, sock, i, c;
	ssize_t            w;
	struct sockaddr_un saddr;
	struct timeval     timeout = {1, 0};
	pid_t              pid;
	uint64_t           v[COUNTER_LAST];
	struct sigaction   act;

	if ((pid = fork()) == -1) {
		xlog_strerror(LOG_ERR, errno, "fork");
		return -1;
	}
	if (pid > 0)
		return 0;

	setproctitle("counters");
	xlog_init(program, NULL, NULL, 1);

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		exit(1);
	}
	unlink(mdrd_conf.counters_sock);

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		exit(1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, mdrd_conf.counters_sock,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "bind");
		exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		exit(1);
	}

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = &counters_sig_handler;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1 ||
	    sigaction(SIGCHLD, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "sigaction");
		exit(1);
	}

	while (!shutdown_triggered) {
		if ((sock = accept(lsock, NULL, 0)) == -1) {
			if (errno == EINTR)
				continue;
			xlog_strerror(LOG_ERR, errno, "accept");
			exit(1);
		}

		if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
			xlog_strerror(LOG_ERR, errno, "fcntl");
			close(sock);
			continue;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		    sizeof(timeout)) == -1) {
			xlog_strerror(LOG_ERR, errno, "setsockopt");
			close(sock);
			continue;
		}

		if ((pid = fork()) == -1) {
			xlog_strerror(LOG_ERR, errno, "fork");
			continue;
		}

		if (pid > 0) {
			close(sock);
			continue;
		}

		close(lsock);
		for (i = 0; i < counters_arena_count(); i++) {
			counters_set_arena(i);
			for (c = 0; c < COUNTER_LAST; c++)
				v[c] = counters_get(c);
again:
			w = write(sock, v, sizeof(v));
			if (w == -1) {
				if (errno == EINTR)
					goto again;
				xlog_strerror(LOG_ERR, errno, "write");
				goto end;
			}

			if (w < sizeof(v)) {
				xlog(LOG_ERR, NULL, "short write");
				goto end;
			}
		}
end:
		exit(0);
	}
	/* Never reached */
	return 0;
}

void
send_shutdown()
{
	FILE *f;
	char  p[11];
	pid_t pid;

	if ((f = fopen(mdrd_conf.pid_file, "r")) == NULL)
		err(1, "fopen");
	if (fgets(p, sizeof(p), f) == NULL) {
		if (ferror(f))
			err(1, "fgets");
		else
			errx(1, "fgets: pid file was empty");
	}
	fclose(f);

	pid = atoi(p);
	if (pid <= 1)
		errx(1, "shutdown: pid file contained an invalid value");
	if (kill(pid, 15) == -1)
		err(1, "kill");
}

int
main(int argc, char **argv)
{
	int                opt;
	SSL_CTX           *ctx;
	struct xerr        e;
	int                lsock[2];
	size_t             lsock_len = 0;
	int                n_children, i;
	int                cntra_idx;
	int                wstatus;
	pid_t              pid;
	struct sigaction   act;
	struct rlimit      zero_core = {0, 0};

	while ((opt = getopt(argc, argv, "c:hfd")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'c':
			strlcpy(config_file_path, optarg,
			    sizeof(config_file_path));
			break;
		case 'd':
			debug = 1;
			/* fallthrough; debug implies foreground */
		case 'f':
			foreground = 1;
			break;
		}
	}

	switch (flatconf_read(config_file_path, flatconf_vars, NULL)) {
	case 0:
		/* Success */
		break;
	case 1:
		errx(1, "flatconf: configuration is not valid");
	case 2:
		errx(1, "flatconf: memory exchaused by parser");
	default:
		err(1, "flatconf_read");
	}

	if (argc > optind) {
		if (strcmp(argv[optind], "shutdown") == 0) {
			send_shutdown();
			exit(0);
		} else if (strcmp(argv[optind], "stat") == 0) {
			/*
			 * Block most common signals to avoid exiting while
			 * holding the counter read lock.
			 */
			if (sigaction(SIGINT, &act, NULL) == -1 ||
			    sigaction(SIGHUP, &act, NULL) == -1 ||
			    sigaction(SIGQUIT, &act, NULL) == -1 ||
			    sigaction(SIGTERM, &act, NULL) == -1) {
				err(1, "sigaction");
			}
			counters_read(mdrd_conf.counters_sock);
			exit(0);
		}
		usage();
		errx(1, "unknown command");
	}

	if (mdrd_conf.backend_argv == NULL)
		errx(1, "no backend_argv specified");

	if (mdrd_conf.port < 1 || mdrd_conf.port > 65535)
		errx(1, "invalid listen port specified");

	if (mdrd_conf.listen_backlog < 1)
		errx(1, "invalid listen backlog size specified");

	if (mdrd_conf.socket_timeout_min >= INT_MAX)
		errx(1, "invalid min socket timeout");
	if (mdrd_conf.socket_timeout_max >= INT_MAX)
		errx(1, "invalid max socket timeout");
	if (mdrd_conf.socket_timeout_min >
	    mdrd_conf.socket_timeout_max)
		errx(1, "socket timeout min > max");

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = handle_signals;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		err(1, "sigaction");
	}

	if (!foreground) {
		if (daemonize(program, mdrd_conf.pid_file,
		    0, 0, &e) == -1) {
			xerr_print(&e);
			exit(1);
		}
	} else {
		xlog_init(program, (debug) ? "all" : NULL, NULL, 1);
	}

	if (spawnproc_init(&sproc, mdrd_conf.backend_promises,
	    mdrd_conf.backend_unveils) == -1)
		err(1, "spawnproc_init");

	load_keys();

	if (!mdrd_conf.enable_coredumps &&
	    setrlimit(RLIMIT_CORE, &zero_core) == -1)
			err(1, "setrlimit");

	if (geteuid() == 0) {
		if (drop_privileges(mdrd_conf.gid,
		    mdrd_conf.uid, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
	}

#ifdef __OpenBSD__
	if (unveil(mdrd_conf.backend_argv[0], "x") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", mdrd_conf.backend_argv[0]);
		exit(1);
	}
	if (unveil(mdrd_conf.ca_file, "r") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", mdrd_conf.ca_file);
		exit(1);
	}
	if (unveil(mdrd_conf.crl_file, "r") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", mdrd_conf.crl_file);
		exit(1);
	}
	if (pledge("stdio rpath cpath recvfd inet dns proc", "") == -1) {
		xlog_strerror(LOG_ERR, errno, "pledge");
		exit(1);
	}
#endif
	if ((ctx = SSL_CTX_new(TLS_method())) == NULL) {
		xlog(LOG_ERR, NULL, "SSL_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	SSL_CTX_set_security_level(ctx, 3);
	SSL_CTX_set_cert_store(ctx, store);
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback_daemon);

	/*
	 * Disable internal session caching since we prefork multiple processes
	 * and clients may not hit the same process after reconnecting. If
	 * we want resumption we'll use session tickets. See:
	 *   SSL_CTX_set_tlsext_ticket_key_evp_cb(3SSL)
	 */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (SSL_CTX_use_certificate(ctx, ca_crt) != 1) {
		xlog(LOG_ERR, NULL, "SSL_CTX_use_certificate: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
		xlog(LOG_ERR, NULL, "SSL_CTX_use_PrivateKey: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	lsock[lsock_len] = get_listen_socket(AF_INET6, SOCK_STREAM,
	    mdrd_conf.port);
	if (lsock[lsock_len] == -1)
		exit(1);
	lsock_len++;
#ifdef __OpenBSD__
	/*
	 * On OpenBSD, we don't get v4 compatibility when creating a v6
	 * listening socket. This function lets us create listening sockets by
	 * family.
	 */
	lsock[lsock_len] = get_listen_socket(AF_INET, SOCK_STREAM,
	    mdrd_conf.port);
	if (lsock[lsock_len] == -1)
		exit(1);
	lsock_len++;
#endif
	ssl_data_idx = SSL_get_ex_new_index(0, "tlsev_idx", NULL, NULL, NULL);

	backend_reader.cb = &backend_msg_in_cb;
	if (mdrd_conf.prefork <= 0 || foreground) {
		if ((counters_init(1)) == -1) {
			xlog_strerror(LOG_ERR, errno, "counters_init");
			exit(1);
		}
		if (counter_reader() == -1)
			exit(1);
		if (spawnproc_exec(&sproc, mdrd_conf.backend_argv,
		    &backend_wfd, &backend_reader.fd, mdrd_conf.backend_uid,
		    mdrd_conf.backend_gid, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		exit(run(ctx, lsock, lsock_len));
	}

	if ((counters_init(mdrd_conf.prefork)) == -1) {
		xlog_strerror(LOG_ERR, errno, "counters_init");
		exit(1);
	}
	if (counter_reader() == -1)
		exit(1);

	for (n_children = 0; n_children < mdrd_conf.prefork; n_children++) {
		if (spawnproc_exec(&sproc, mdrd_conf.backend_argv,
		    &backend_wfd, &backend_reader.fd, mdrd_conf.backend_uid,
		    mdrd_conf.backend_gid, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}

		counters_set_arena(n_children);
		if ((pid = fork()) == -1) {
			xlog_strerror(LOG_ERR, errno, "fork");
			exit(1);
		} else if (pid == 0) {
			setproctitle("listener");
			exit(run(ctx, lsock, lsock_len));
		}
		counters_set_pid(pid);

		close(backend_reader.fd);
		close(backend_wfd);
	}

	setproctitle("parent");

	for (;;) {
		pid = waitpid(-1, &wstatus, 0);
		if (pid != -1 && !shutdown_triggered) {
			if ((cntra_idx = counters_find_arena(pid)) == -1) {
				xlog(LOG_DEBUG, NULL, "%s: failed to find "
				    "counter arena for pid %d; possibly a "
				    "non-listener child", __func__, pid);
				continue;
			}
			counters_set_arena(cntra_idx);
			counters_set_pid(-1);
			n_children--;
			if (WIFEXITED(wstatus))
				xlog(LOG_WARNING, NULL,
				    "child %d exited with status %d",
				    pid, WEXITSTATUS(wstatus));
			else
				xlog(LOG_WARNING, NULL,
				    "child %d killed by signal %d",
				    pid, WTERMSIG(wstatus));

			if (spawnproc_exec(&sproc, mdrd_conf.backend_argv,
			    &backend_wfd, &backend_reader.fd,
			    mdrd_conf.backend_uid, mdrd_conf.backend_gid,
			    xerrz(&e)) == -1) {
				xlog(LOG_ERR, &e, __func__);
				exit(1);
			}

			counters_incr(COUNTER_RESTARTS);
			if ((pid = fork()) == -1) {
				xlog_strerror(LOG_ERR, errno, "fork");
			} else if (pid == 0) {
				setproctitle("listener");
				exit(run(ctx, lsock, lsock_len));
			} else {
				counters_set_pid(pid);
				n_children++;
			}

			close(backend_reader.fd);
			close(backend_wfd);
			continue;
		}

		if (!shutdown_triggered) {
			xlog(LOG_WARNING, NULL, "signal received but "
			    "shutdown not yet triggered");
			continue;
		}

		if (lsock_len > 0) {
			for (i = 0; i < lsock_len; i++)
			    close(lsock[i]);
			lsock_len = 0;

			sigemptyset(&act.sa_mask);
			act.sa_flags = 0;
			act.sa_handler = SIG_IGN;
			sigaction(SIGINT, &act, NULL);
			sigaction(SIGTERM, &act, NULL);

			kill(0, 15);
		}

		if (pid != -1) {
			if (WIFEXITED(wstatus))
				xlog(LOG_NOTICE, NULL,
				    "child %d exited with status %d",
				    pid, WEXITSTATUS(wstatus));
			else
				xlog(LOG_NOTICE, NULL,
				    "child %d killed by signal %d",
				    pid, WTERMSIG(wstatus));
			n_children--;
			if (n_children == 0)
				break;
		}
	}
	SSL_CTX_free(ctx);
	tlsev_destroy(&listener);
	xlog(LOG_NOTICE, NULL, "all children exited");
	return 0;
}
