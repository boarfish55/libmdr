#ifndef TLSEV_H
#define TLSEV_H

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <netdb.h>
#include "idxheap.h"
#include "xlog.h"

#define TLSEV_IO_SIZE     32768
#define TLSEV_MAX_CLIENTS 1000000000

struct tlsev;

struct tlsev_fd_cb {
	int  fd;
	int  (*cb)(int fd);
};

struct tlsev_peer {
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} addr;

	sa_family_t          sa_family;
	int                  count;
	RB_ENTRY(tlsev_peer) entry;
};
RB_HEAD(tlsev_peer_tree, tlsev_peer);

struct tlsev_listener {
	SSL_CTX                *ctx;
	int                    *lsock;
	size_t                  lsock_len;
	int                     socket_timeout_min;
	int                     socket_timeout_max;
	int                     tlsev_data_idx;
	uint64_t                next_id;
	struct idxheap          tlsev_store;
	struct tlsev_peer_tree  peer_tree;
	struct timespec         last_purge;
	volatile sig_atomic_t   shutdown_triggered;

	int                     active_clients;
	int                     accepting;
	uint32_t                max_clients;
	uint16_t                max_conn_per_ip;
	int                     use_rcv_lowat;

#ifdef __OpenBSD__
	int                     kq;
	/*
	 * This needs to be here so we can resize it when we add new
	 * fd callbacks.
	 */
	struct kevent          *events;
	struct kevent          *ch;
	int                     chn;
	int                     max_ch;
#else
	int                     epollfd;
	struct epoll_event     *events;
#endif
	int                     max_events;

	int  (*client_msg_in_cb)(struct tlsev *, const char *, size_t, void **);
	void (*client_cb_data_free)(struct tlsev *, void *);

	struct tlsev_fd_cb    *fd_callbacks;
	size_t                 fd_callbacks_sz;
	size_t                 fd_callbacks_used;
};

struct tlsev {
	struct tlsev_listener *listener;
	uint64_t               id;
	int                    fd;
	SSL                   *ssl;
	BIO                   *r;
	BIO                   *w;
	int                    wpending;
	int                    reads_paused;
	int                    rcvlowat;
	int                    tlswant;
	int                    drain;
	struct timespec        last_used_at;

	struct sockaddr_in6    peer_addr;
	socklen_t              peer_len;
	X509                  *peer_cert;

	char                  *retry_buf;
	char                  *retry_buf_pos;
	int                    retry_len;

	void                  *client_cb_data;
};

int                  tlsev_init(struct tlsev_listener *, SSL_CTX *, int *,
                         size_t, int, int, uint32_t, uint16_t, int, int,
                         int (*in_cb)(struct tlsev *, const char *,
                         size_t, void **),
                         void (*in_cb_data_free)(struct tlsev *, void *));
int                  tlsev_add_fd_cb(struct tlsev_listener *,
                         struct tlsev_fd_cb *);
void                 tlsev_destroy(struct tlsev_listener *);
int                  tlsev_run(struct tlsev_listener *);
void                 tlsev_shutdown(struct tlsev_listener *);
X509                *tlsev_peer_cert(struct tlsev *);
struct sockaddr_in6 *tlsev_peer(struct tlsev *);
int                  tlsev_reply(struct tlsev *, const char *, int);
void                 tlsev_drain(struct tlsev *);
uint64_t             tlsev_id(struct tlsev *);
int                  tlsev_fd(struct tlsev *);
struct tlsev *       tlsev_get(struct tlsev_listener *, int);

#endif
