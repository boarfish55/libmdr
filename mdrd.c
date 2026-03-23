#include <sys/file.h>
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
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "counters.h"
#include "flatconf.h"
#include "mdr.h"
#include "mdrd.h"
#include "util.h"
#include "tlsev.h"
#include "xlog.h"

const char *program = "mdrd";
X509_STORE *store = NULL;
EVP_PKEY   *priv_key = NULL;

struct spawnproc      sproc;
struct tlsev_listener listener;
struct tlsev_fd_cb    backend_reader;
int                   backend_wfd;
pid_t                 backend_pid = 0;
volatile sig_atomic_t shutdown_triggered = 0;
volatile sig_atomic_t reload_cert = 0;
struct timespec       last_cert_mtime;

int  foreground = 0;
int  debug = 0;
int  ssl_data_idx;
char config_file_path[PATH_MAX] = "/etc/mdrd.conf";

uint32_t *allowed_mdr_domains = NULL;
int       allowed_mdr_domains_count = 0;

extern char *optarg;
extern int   optind, opterr, optopt;

struct {
	char *uid;
	char *gid;
	int   enable_coredumps;

	char  counters_sock[PATH_MAX];
	char  pid_file[PATH_MAX];
	char  ca_file[PATH_MAX];
	char  cert_file[PATH_MAX];
	char  crl_file[PATH_MAX];
	char  crl_path[PATH_MAX];
	char  key_file[PATH_MAX];
	int   require_client_cert;
	int   monitor_cert;

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

	uint64_t **allowed_mdr_domains;
	uint64_t   dbg_delay_to_backend_seconds;

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
	"",
	"",
	"",
	"",
	"",
	0,
	1,
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
	0,
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
		"cert_file",
		FLATCONF_STRING,
		mdrd_conf.cert_file,
		sizeof(mdrd_conf.cert_file)
	},
	{
		"crl_file",
		FLATCONF_STRING,
		mdrd_conf.crl_file,
		sizeof(mdrd_conf.crl_file)
	},
	{
		"crl_path",
		FLATCONF_STRING,
		mdrd_conf.crl_path,
		sizeof(mdrd_conf.crl_path)
	},
	{
		"key_file",
		FLATCONF_STRING,
		mdrd_conf.key_file,
		sizeof(mdrd_conf.key_file)
	},
	{
		"require_client_cert",
		FLATCONF_BOOLINT,
		&mdrd_conf.require_client_cert,
		sizeof(mdrd_conf.require_client_cert)
	},
	{
		"monitor_cert",
		FLATCONF_BOOLINT,
		&mdrd_conf.monitor_cert,
		sizeof(mdrd_conf.monitor_cert)
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
		"allowed_mdr_domains",
		FLATCONF_ALLOCULONGLIST,
		&mdrd_conf.allowed_mdr_domains,
		0
	},
	{
		"dbg_delay_to_backend_seconds",
		FLATCONF_ULONG,
		&mdrd_conf.dbg_delay_to_backend_seconds,
		sizeof(mdrd_conf.dbg_delay_to_backend_seconds)
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
pack_bereq(struct pmdr *m, uint64_t id, int fd, struct sockaddr_in6 *peer,
    struct umdr *msg, X509 *peer_cert)
{
	size_t           cert_len;
	unsigned char   *cert_buf;
	struct pmdr_vec  pv[6];

	cert_len = i2d_X509(peer_cert, NULL);
	if (cert_len < 0) {
		xlog(LOG_ERR, NULL, "%s: i2d_X509() < 0", __func__);
		return -1;
	}

	if (cert_len > mdrd_conf.max_cert_size) {
		xlog(LOG_ERR, NULL, "%s: X509 length above limit: "
		    "%lu > %lu", __func__, cert_len, mdrd_conf.max_cert_size);
	}

	pv[0].type = MDR_U64;
	pv[0].v.u64 = id;
	pv[1].type = MDR_I32;
	pv[1].v.i32 = fd;
	pv[2].type = MDR_B;
	pv[2].v.b.bytes = (peer->sin6_family == AF_INET6)
	    ? peer->sin6_addr.s6_addr
	    : (uint8_t *)&(((struct sockaddr_in *)peer)->sin_addr.s_addr);
	pv[2].v.b.sz = (peer->sin6_family == AF_INET6) ? 16 : 4;
	pv[3].type = MDR_U16;
	pv[3].v.u16 = (peer->sin6_family == AF_INET6)
	    ? ntohs(peer->sin6_port)
	    : ntohs(((struct sockaddr_in *)peer)->sin_port);
	pv[4].type = MDR_M;
	pv[4].v.umdr = msg;
	pv[5].type = MDR_RSVB;
	pv[5].v.rsvb.dst = (void **)&cert_buf;
	pv[5].v.rsvb.sz = cert_len;
	if (pmdr_pack(m, mdr_msg_mdrd_bein, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
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
		xlog(LOG_NOTICE, NULL, "verify error for %s (%s:%s): %s%s\n",
		    name, hbuf, sbuf, X509_verify_cert_error_string(e),
		    (mdrd_conf.require_client_cert)
		    ? ""
		    : "; valid cert not required so allowing anyway");
	}
	return ok || !mdrd_conf.require_client_cert;
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
	switch (sig) {
	case SIGHUP:
		reload_cert = 1;
		break;
	case SIGTERM:
	case SIGINT:
	default:
		shutdown_triggered = 1;
		tlsev_shutdown(&listener);
	}
}

struct client_cb_data {
	size_t       len;
	char        *buf;
	size_t       buf_sz;
	struct umdr  msg;
	int          send_cert;
};

void
client_close_cb(struct tlsev *t, void *data)
{
	struct pmdr     bemsg;
	struct pmdr_vec pv[1];
	char            buf[mdr_hdr_size(0) + sizeof(uint64_t)];

	pmdr_init(&bemsg, buf, sizeof(buf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = tlsev_id(t);
	if (pmdr_pack(&bemsg, mdr_msg_mdrd_beclose, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: pmdr_pack", __func__);
	} else {
		if (writeall(backend_wfd, pmdr_buf(&bemsg),
		    pmdr_size(&bemsg)) == -1)
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
	}

	struct client_cb_data *cb_data = (struct client_cb_data *)data;
	if (cb_data->buf != NULL)
		free(cb_data->buf);
	free(cb_data);
}

/*
 * Message is coming from remote client, we're passing it to the
 * backend.
 */
int
client_msg_in_cb(struct tlsev *t, const char *buf, size_t n, void **data)
{
	struct client_cb_data *cb_data = (struct client_cb_data *)(*data);
	void                  *tmp;
	struct pmdr            bereq;
	char                   bereq_buf[mdrd_conf.max_payload_size + 4096];
	int                    status, i;
	struct timespec        ts;

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
			return -1;
		}
		cb_data->buf = tmp;
		cb_data->buf_sz = cb_data->len + n;
	}

	memcpy(cb_data->buf + cb_data->len, buf, n);
	cb_data->len += n;

	if (umdr_init(&cb_data->msg, cb_data->buf, cb_data->len,
	    MDR_FNONE) == MDR_FAIL) {
		// TODO: send an error to the client, possibly
		// that we couldn't support the extensions, or that
		// the payload was too large.
		xlog_strerror(LOG_ERR, errno, "%s: umdr_init", __func__);
		return -1;
	}

	if (umdr_size(&cb_data->msg) > mdrd_conf.max_payload_size) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr size is above our "
		    "configured maximum size of %lu", __func__,
		    mdrd_conf.max_payload_size);
		return -1;
	}

	if (umdr_pending(&cb_data->msg) > 0) {
		errno = EAGAIN;
		return 0;
	}

	counters_incr(COUNTER_MESSAGES_IN);

	for (i = 0; mdrd_conf.allowed_mdr_domains &&
	    mdrd_conf.allowed_mdr_domains[i] != NULL; i++) {
		if (umdr_domain(&cb_data->msg) ==
		    *mdrd_conf.allowed_mdr_domains[i])
			break;
	}
	if (mdrd_conf.allowed_mdr_domains[i] == NULL) {
		counters_incr(COUNTER_MESSAGES_IN_DENIED);
		xlog(LOG_ERR, NULL,
		    "%s: domain not allowed", __func__);
		return -1;
	}

	pmdr_init(&bereq, bereq_buf, sizeof(bereq_buf), MDR_FNONE);
	if ((status = pack_bereq(&bereq, tlsev_id(t), tlsev_fd(t),
	    tlsev_peer(t), &cb_data->msg,
	    (cb_data->send_cert) ? tlsev_peer_cert(t) : NULL)) == 0) {
		/*
		 * We only sent the cert the first time; backend should
		 * remember it.
		 */
		cb_data->send_cert = 0;

		/*
		 * Useful for debugging backends, to give time to attach
		 * with a debugger.
		 */
		if (mdrd_conf.dbg_delay_to_backend_seconds > 0) {
			xlog(LOG_NOTICE, NULL, "holding before passing "
			    "message to our child (pid %u)", backend_pid);
			ts.tv_sec = mdrd_conf.dbg_delay_to_backend_seconds;
			ts.tv_nsec = 0;
			nanosleep(&ts, NULL);
		}

		if ((status = writeall(backend_wfd, pmdr_buf(&bereq),
		    pmdr_size(&bereq))) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		}
	}

	memmove(cb_data->buf, cb_data->buf + umdr_size(&cb_data->msg),
	    cb_data->len - umdr_size(&cb_data->msg));
	cb_data->len -= umdr_size(&cb_data->msg);
	return status;
}

/*
 * A message comes from our backend, destined for the remote client.
 */
int
backend_msg_in_cb(int fd)
{
	struct umdr      beout;
	struct pmdr      reply;
	char             beout_buf[mdrd_conf.max_payload_size + 64];
	char             reply_buf[32];
	struct tlsev    *t;
	uint64_t         id;
	int              tlsfd, r;
	uint32_t         beout_flags;
	struct umdr_vec  uv[4];
	struct pmdr_vec  pv[1];

	if ((r = mdr_buf_from_fd(fd, beout_buf,
	    sizeof(beout_buf))) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: mdr_buf_from_fd", __func__);
		goto fail;
	}

	if (r == 0) {
		xlog(LOG_ERR, NULL,
		    "%s: mdr_buf_from_fd: EOF from backend", __func__);
		goto fail;
	}

	if (umdr_init(&beout, beout_buf, r, MDR_FNONE) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: umdr_init/beout", __func__);
		goto fail;
	}

	switch (umdr_dcv(&beout)) {
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&beout, mdr_msg_error,
		    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: umdr_unpack/mdr_msg_error", __func__);
			goto fail;
		}
		xlog(LOG_ERR, NULL,
		    "%s: error from backend: code=%u, msg=%s",
		    __func__, uv[0].v.u32, uv[1].v.s.bytes);
		goto fail;
	case MDR_DCV_MDRD_BEOUT:
		if (umdr_unpack(&beout, mdr_msg_mdrd_beout,
		    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: umdr_unpack/mdr_msg_mdrd_beout", __func__);
			goto fail;
		}
		break;
	case MDR_DCV_MDRD_BEOUT_EMPTY:
		if (umdr_unpack(&beout, mdr_msg_mdrd_beout_empty,
		    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: umdr_unpack/mdr_msg_mdrd_beout_empty",
			    __func__);
			goto fail;
		}
		break;
	default:
		xlog(LOG_ERR, NULL,
		    "%s: unknown message from backend: %x",
		    __func__, umdr_dcv(&beout));
	}

	id = uv[0].v.u64;
	tlsfd = uv[1].v.i32;
	beout_flags = uv[2].v.u32;

	pmdr_init(&reply, reply_buf, sizeof(reply_buf), MDR_FNONE);

	if ((t = tlsev_get(&listener, tlsfd)) == NULL) {
		xlog(LOG_ERR, NULL,
		    "%s: tlsev_get on fd %d not found", __func__, fd);
		pv[0].type = MDR_U64;
		pv[0].v.u64 = id;
		if (pmdr_pack(&reply, mdr_msg_mdrd_besesserr,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
			xlog(LOG_ERR, NULL,
			    "%s: pmdr_pack/mdr_msg_mdrd_besesserr", __func__);
			return 1;
		}
		// TODO: possible deadlock with full buffer
		if (writeall(backend_wfd, pmdr_buf(&reply),
		    pmdr_size(&reply)) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		}
		return 1;
	}

	if (tlsev_id(t) != id) {
		xlog(LOG_ERR, NULL,
		    "%s: received beout from backend for a client that is "
		    " gone on fd %d", __func__, tlsfd);
		pv[0].type = MDR_U64;
		pv[0].v.u64 = id;
		if (pmdr_pack(&reply, mdr_msg_mdrd_besesserr,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
			xlog(LOG_ERR, NULL,
			    "%s: pmdr_pack/mdr_msg_mdrd_besesserr", __func__);
			return 1;
		}
		// TODO: possible deadlock with full buffer
		if (writeall(backend_wfd, pmdr_buf(&reply),
		    pmdr_size(&reply)) == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		}
		return 1;
	}

	if (umdr_dcv(&beout) == MDR_DCV_MDRD_BEOUT_EMPTY) {
		if (beout_flags & MDRD_BEOUT_FCLOSE)
			tlsev_drain(t);
		return 1;
	}

	if ((r = tlsev_reply(t, umdr_buf(&uv[3].v.m),
	    umdr_size(&uv[3].v.m))) <= 0 ||
	    beout_flags & MDRD_BEOUT_FCLOSE)
		tlsev_drain(t);

	counters_incr(COUNTER_MESSAGES_OUT);

	/*
	 * TODO: backend could overflow us here. We should cap how many
	 * bytes pending we have and create a message to tell our backend
	 * to stop pause message for this client.
	 * This only matters in a "streaming" situation where we don't
	 * have 1:1 requests/replies. We'll need a message serial number
	 * to properly inform the backend where to resme.
	 * The code above assumes we get a "beout" from the backend,
	 * always, so it's not yet able to support this kind of streaming.
	 */

	return 1;
fail:
	/*
	 * We completely shutdown when getting we can't properly decode
	 * from the backend because chances are we may not be able to
	 * recover.
	 */
	tlsev_shutdown(&listener);
	shutdown_triggered = 1;
	return 0;
}

static int
load_crl(const char *crl_path, struct xerr *e)
{
	X509_CRL *crl;
	FILE     *f;

	if ((f = fopen(crl_path, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s", crl_path);

	if ((crl = PEM_read_X509_CRL(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509_CRL");
	}

	fclose(f);

	if (!X509_STORE_add_crl(store, crl))
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_STORE_add_crl");
	return 0;
}

int
load_keys(struct xerr *e)
{
	FILE          *f;
	DIR           *d;
	struct dirent *de;
	int            de_len;
	char           crl_path[PATH_MAX + NAME_MAX + 1];
	X509          *crt;

	if ((f = fopen(mdrd_conf.key_file, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    mdrd_conf.key_file);
	if ((priv_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "PEM_read_PrivateKey");
		fclose(f);
		return -1;
	}
	fclose(f);

	if ((store = X509_STORE_new()) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_new");

	if ((f = fopen(mdrd_conf.ca_file, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    mdrd_conf.ca_file);
	if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
	}
	fclose(f);
	if (!X509_STORE_add_cert(store, crt)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_add_cert");
		X509_free(crt);
		return -1;
	}

	if (*mdrd_conf.crl_path != '\0') {
		if ((d = opendir(mdrd_conf.crl_path)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "opendir: %s",
			    mdrd_conf.crl_path);

		for (;;) {
			errno = 0;
			de = readdir(d);
			if (de == NULL) {
				if (errno == 0)
					break;
				closedir(d);
				return XERRF(e, XLOG_ERRNO, errno,
				    "readdir: %s", mdrd_conf.crl_path);
			}
			if (de->d_type != DT_REG)
				continue;
			de_len = strlen(de->d_name);
			if (strcmp(de->d_name + (de_len - 4), ".crl") != 0)
				continue;

			snprintf(crl_path, sizeof(crl_path), "%s/%s",
			    mdrd_conf.crl_path, de->d_name);
			if (load_crl(crl_path, xerrz(e)) == -1) {
				closedir(d);
				return XERR_PREPENDFN(e);
			}
		}
		closedir(d);
	}

	if (*mdrd_conf.crl_file != '\0') {
		if (load_crl(mdrd_conf.crl_file, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
	}

	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL))
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_STORE_set_flags");

	return 0;
}

void
cleanup()
{
	mdr_registry_clear();
	flatconf_free(flatconf_vars);
	if (priv_key != NULL) {
		EVP_PKEY_free(priv_key);
		priv_key = NULL;
	}
}

int
reload_cert_cb(void *args)
{
	int          fd;
	struct stat  st;
	SSL_CTX     *ctx = (SSL_CTX *)args;

	if (ctx == NULL)
		return 0;

	if (!reload_cert && !mdrd_conf.monitor_cert)
		return 1;

	if (stat(mdrd_conf.cert_file, &st) == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: stat: %s", __func__, mdrd_conf.cert_file);
		return 0;
	}

	if (timespeccmp(&st.st_mtim, &last_cert_mtime, ==) == 0)
		return 1;

	if ((fd = open(mdrd_conf.cert_file, O_RDONLY)) == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: open: %s", __func__, mdrd_conf.cert_file);
		return 0;
	}
	if (flock(fd, LOCK_SH) == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: flock: %s", __func__, mdrd_conf.cert_file);
		close(fd);
		return 0;
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, mdrd_conf.cert_file) != 1) {
		xlog(LOG_ERR, NULL, "SSL_CTX_use_certificate: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		close(fd);
		return 0;
	}
	close(fd);

	memcpy(&last_cert_mtime, &st.st_mtim, sizeof(last_cert_mtime));
	reload_cert = 0;
	return 1;
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
	status = tlsev_run(&listener, &reload_cert_cb, ctx);
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
}

void
counter_reader()
{
	int                lsock, sock, i, c, r;
	ssize_t            w;
	struct sockaddr_un saddr;
	struct timeval     timeout = {1, 0};
	pid_t              pid;
	uint64_t           v[COUNTER_LAST];
	struct sigaction   act;
	struct pollfd      pfd;

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
	if (fcntl(lsock, F_SETFD, O_NONBLOCK) == -1) {
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
		pfd.fd = lsock;
		pfd.events = POLLIN;
		r = poll(&pfd, 1, 1000);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			xlog_strerror(LOG_ERR, errno, "poll");
			exit(1);
		}

		if (r == 0) {
			if (getppid() == 1)
				shutdown_triggered = 1;
			continue;
		}

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
		cleanup();
		exit(0);
	}
	cleanup();
	exit(0);
}

void
send_shutdown()
{
	FILE *f;
	char  p[11];
	pid_t pid;

	if ((f = fopen(mdrd_conf.pid_file, "r")) == NULL)
		err(1, "fopen: %s", mdrd_conf.pid_file);
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

	/*
	 * Most settings cannot be reloaded without restarting the daemon
	 * so we don't reload the config on SIGHUP.
	 */
	switch (flatconf_read(config_file_path, flatconf_vars, NULL)) {
	case 0:
		/* Success */
		break;
	case 1:
		errx(1, "flatconf: configuration is not valid");
	case 2:
		errx(1, "flatconf: memory exhausted by parser");
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

	if (mdr_register_builtin_specs() == MDR_FAIL)
                err(1, "mdr_register_builtin_specs");

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
	    sigaction(SIGHUP, &act, NULL) == -1 ||
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

	if (load_keys(xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		exit(1);
	}

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
	// TODO: We should use Linux's landlock when it stabilizes and
	// becomes mainstream on Debian
	if (unveil(mdrd_conf.backend_argv[0], "x") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", mdrd_conf.backend_argv[0]);
		exit(1);
	}
	if (unveil(mdrd_conf.cert_file, "r") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", mdrd_conf.cert_file);
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
	if (mdrd_conf.require_client_cert)
		SSL_CTX_set_verify(ctx,
		    SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		    verify_callback_daemon);
	else
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,
		    verify_callback_daemon);

	/*
	 * Disable internal session caching since we prefork multiple processes
	 * and clients may not hit the same process after reconnecting. If
	 * we want resumption we'll use session tickets. See:
	 *   SSL_CTX_set_tlsext_ticket_key_evp_cb(3SSL)
	 */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (SSL_CTX_use_certificate_chain_file(ctx, mdrd_conf.cert_file) != 1) {
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
#ifndef __linux__
	/*
	 * On OpenBSD (and other BSDs??), we don't get v4 compatibility when
	 * creating a v6 listening socket. This function lets us create
	 * listening sockets by family.
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

		if ((pid = fork()) == -1) {
			xlog_strerror(LOG_ERR, errno, "fork");
			return -1;
		} else if (pid == 0) {
			SSL_CTX_free(ctx);
			spawnproc_close(&sproc);
			counter_reader();
		}

		if (spawnproc_exec(&sproc, mdrd_conf.backend_argv,
		    &backend_pid, &backend_wfd, &backend_reader.fd,
		    mdrd_conf.backend_uid, mdrd_conf.backend_gid,
		    xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		exit(run(ctx, lsock, lsock_len));
	}

	if ((counters_init(mdrd_conf.prefork)) == -1) {
		xlog_strerror(LOG_ERR, errno, "counters_init");
		exit(1);
	}

	if ((pid = fork()) == -1) {
		xlog_strerror(LOG_ERR, errno, "fork");
		return -1;
	} else if (pid == 0) {
		SSL_CTX_free(ctx);
		counter_reader();
	}

	for (n_children = 0; n_children < mdrd_conf.prefork; n_children++) {
		if (spawnproc_exec(&sproc, mdrd_conf.backend_argv,
		    &backend_pid, &backend_wfd, &backend_reader.fd,
		    mdrd_conf.backend_uid, mdrd_conf.backend_gid,
		    xerrz(&e)) == -1) {
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
			    &backend_pid, &backend_wfd, &backend_reader.fd,
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
