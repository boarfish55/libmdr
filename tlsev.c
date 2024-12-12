#include <sys/types.h>
#ifdef __OpenBSD__
#include <sys/event.h>
#include <sys/time.h>
#else
#include <sys/epoll.h>
#endif
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include "tlsev.h"
#include "idxheap.h"

static int
tlsev_peer_tree_cmp(struct tlsev_peer *p1, struct tlsev_peer *p2)
{
	if (p1->sa_family - p2->sa_family != 0)
		return p1->sa_family - p2->sa_family;

	if (p1->sa_family == AF_INET) {
		if (p1->addr.v4.s_addr > p2->addr.v4.s_addr)
			return 1;
		else if (p1->addr.v4.s_addr < p2->addr.v4.s_addr)
			return -1;
		return 0;
	}
	return memcmp(&p1->addr.v6.s6_addr, &p2->addr.v6.s6_addr,
	    sizeof(p1->addr.v6.s6_addr));
}

RB_PROTOTYPE(tlsev_peer_tree, tlsev_peer, entry, tlsev_peer_tree_cmp);
RB_GENERATE(tlsev_peer_tree, tlsev_peer, entry, tlsev_peer_tree_cmp);

static int
tlsev_timeout_cmp(const void *k1, const void *k2)
{
	struct timespec *t1, *t2;

	t1 = &((struct tlsev *)k1)->last_used_at;
	t2 = &((struct tlsev *)k2)->last_used_at;

	if (t1->tv_sec < t2->tv_sec ||
	    (t1->tv_sec == t2->tv_sec && t1->tv_nsec < t2->tv_nsec))
		return -1;

	if (t1->tv_sec > t2->tv_sec ||
	    (t1->tv_sec == t2->tv_sec && t1->tv_nsec > t2->tv_nsec))
		return 1;

	return 0;
}

static int
tlsev_match(const void *k1, const void *k2)
{
	struct tlsev *t1 = (struct tlsev *)k1;
	struct tlsev *t2 = (struct tlsev *)k2;

	return t1->fd == t2->fd;
}

static uint32_t
tlsev_hash(const void *t)
{
	return ((struct tlsev *)t)->fd;
}

static void
tlsev_free(struct tlsev *t)
{
	/* This will free up the associated BIOs */
	SSL_free(t->ssl);

	free(t);
}

static int
tlsev_grow_events_buffer(struct tlsev_listener *l)
{
	void *tmp;
	int   new_max = l->max_events + 1000;

#ifdef __OpenBSD__
	tmp = reallocarray(l->events, sizeof(struct kevent), new_max);
	if (tmp == NULL)
		return -1;
	if (tmp != l->events)
		l->events = (struct kevent *)tmp;
#else
	tmp = reallocarray(l->events, sizeof(struct epoll_event), new_max);
	if (tmp == NULL)
		return -1;
	if (tmp != l->events)
		l->events = (struct epoll_event *)tmp;
#endif
	l->max_events = new_max;
	return 0;
}

#ifdef __OpenBSD__
static int
kq_ev_set(struct tlsev_listener *l, int fd, short filter, u_short flags)
{
	void *tmp;
	int   new_max;

	if (l->chn + 1 >= l->max_ch) {
		new_max = l->chn + 1000;
		xlog(LOG_NOTICE, NULL, "expanding kqueue changelist array "
		    "to %d", new_max);
		tmp = reallocarray(l->ch, sizeof(struct kevent), new_max);
		if (tmp == NULL)
			return -1;
		if (tmp != l->ch)
			l->ch = (struct kevent *)tmp;
		l->max_ch = new_max;
	}

	EV_SET(&l->ch[l->chn++], fd, filter, flags, 0, 0, 0);
	return 0;
}
#endif

int
tlsev_init(struct tlsev_listener *l, SSL_CTX *ctx, int *lsock,
    size_t lsock_len, int socket_timeout_min, int socket_timeout_max,
    uint32_t max_clients, uint16_t max_conn_per_ip, int use_rcv_lowat,
    int ssl_data_idx,
    int (*in_cb)(struct tlsev *, const char *, size_t, void **),
    void (*in_cb_data_free)(void *))
{
	int                n;
#ifdef __OpenBSD__
	struct kevent      ch[lsock_len];
#else
	struct epoll_event ev;
#endif
	if (in_cb == NULL || l == NULL || ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (socket_timeout_min < 0)
		socket_timeout_min = 0;
	if (socket_timeout_max < 0)
		socket_timeout_max = 0;
	if (socket_timeout_max < socket_timeout_min)
		socket_timeout_max = socket_timeout_min;
	if (max_clients < 1)
		max_clients = 1000;
	else if (max_clients > TLSEV_MAX_CLIENTS)
		max_clients = TLSEV_MAX_CLIENTS;

	if (max_conn_per_ip < 1)
		max_conn_per_ip = 10;

	bzero(l, sizeof(struct tlsev_listener));
	l->ctx = ctx;
	l->lsock_len = lsock_len;
	l->socket_timeout_min = socket_timeout_min;
	l->socket_timeout_max = socket_timeout_max;
	l->tlsev_data_idx = ssl_data_idx;
	l->next_id = 1;
	l->in_cb = in_cb;
	l->in_cb_data_free = in_cb_data_free;

	l->max_clients = max_clients;
	l->max_conn_per_ip = max_conn_per_ip;
	l->use_rcv_lowat = use_rcv_lowat;
	l->accepting = 1;

	for (n = 0; n < lsock_len; n++)
		if (fcntl(lsock[n], F_SETFL, O_NONBLOCK) == -1)
			return -1;

	if (idxheap_init(&l->tlsev_store,
	    (max_clients / 2 < 1) ? 2 : max_clients / 2,
	    &tlsev_timeout_cmp, &tlsev_match,
	    (void(*)(void *))&tlsev_free, &tlsev_hash))
		return -1;

	RB_INIT(&l->peer_tree);
	l->lsock = reallocarray(NULL, sizeof(int), l->lsock_len);
	if (l->lsock == NULL) {
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	memcpy(l->lsock, lsock, sizeof(int) * l->lsock_len);
#ifdef __OpenBSD__
	l->max_events = l->max_clients + l->lsock_len;
	l->max_ch = l->max_events;
	l->ch = reallocarray(NULL, sizeof(struct kevent), l->max_ch);
	if (l->ch == NULL) {
		free(l->lsock);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	l->events = malloc(sizeof(struct kevent) * l->max_events);
	if (l->ch == NULL) {
		free(l->lsock);
		free(l->ch);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	if ((l->kq = kqueue()) == -1) {
		free(l->lsock);
		free(l->ch);
		free(l->events);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	for (n = 0; n < l->lsock_len; n++)
		EV_SET(&ch[n], l->lsock[n], EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(l->kq, ch, l->lsock_len, NULL, 0, NULL) == -1) {
		free(l->lsock);
		free(l->ch);
		free(l->events);
		idxheap_free(&l->tlsev_store);
		close(l->kq);
		return -1;
	}
#else
	/* Up to max_clients events, plus listening socket */
	l->max_events = l->max_clients + l->lsock_len;
	l->events = malloc(sizeof(struct epoll_event) * l->max_events);
	if (l->events == NULL) {
		free(l->lsock);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	if ((l->epollfd = epoll_create1(0)) == -1) {
		idxheap_free(&l->tlsev_store);
		free(l->lsock);
		free(l->events);
		return -1;
	}
	for (n = 0; n < l->lsock_len; n++) {
		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN|EPOLLEXCLUSIVE;
		ev.data.fd = l->lsock[n];
		if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD,
		    l->lsock[n], &ev) == -1) {
			idxheap_free(&l->tlsev_store);
			free(l->lsock);
			free(l->events);
			close(l->epollfd);
			return -1;
		}
	}
#endif
	return 0;
}

void
tlsev_del_fd_cb(struct tlsev_listener *l, int i)
{
	for (++i; i < l->fd_callbacks_used; i++)
		memcpy(&l->fd_callbacks[i - 1], &l->fd_callbacks[i],
		    sizeof(struct tlsev_fd_cb));
	l->fd_callbacks_used--;
}

int
tlsev_add_fd_cb(struct tlsev_listener *l, struct tlsev_fd_cb *fd_cb)
{
#ifdef __OpenBSD__
	struct kevent       ch;
#else
	struct epoll_event  ev;
#endif
	void               *tmp;

	if (l == NULL || fd_cb == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (l->max_events >= INT_MAX - 1) {
		errno = EOVERFLOW;
		return -1;
	}

	if (l->fd_callbacks_used >= l->fd_callbacks_sz) {
		tmp = reallocarray(l->fd_callbacks,
		    sizeof(struct tlsev_fd_cb), l->fd_callbacks_sz + 1);
		if (tmp == NULL)
			return -1;
		if (tmp != l->fd_callbacks)
			l->fd_callbacks = (struct tlsev_fd_cb *)tmp;
		l->fd_callbacks_sz++;
	}

	l->fd_callbacks[l->fd_callbacks_used].fd = fd_cb->fd;
	l->fd_callbacks[l->fd_callbacks_used].cb = fd_cb->cb;
	l->fd_callbacks_used++;
#ifdef __OpenBSD__
	EV_SET(&ch, fd_cb->fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(l->kq, &ch, 1, NULL, 0, NULL) == -1)
		return -1;
#else
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = fd_cb->fd;
	if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, fd_cb->fd, &ev) == -1)
		return -1;
#endif
	return 0;
}

void
tlsev_destroy(struct tlsev_listener *l)
{
	idxheap_free(&l->tlsev_store);
	if (l->fd_callbacks)
		free(l->fd_callbacks);
	if (l->events)
		free(l->events);
	if (l->lsock)
		free(l->lsock);
#ifdef __OpenBSD__
	if (l->ch)
		free(l->ch);
	close(l->kq);
#else
	close(l->epollfd);
#endif
}

X509 *
tlsev_peer_cert(struct tlsev *t)
{
	return t->peer_cert;
}

struct sockaddr_in6 *
tlsev_peer(struct tlsev *t)
{
	return &t->peer_addr;
}

uint64_t
tlsev_id(struct tlsev *t)
{
	return t->id;
}

int
tlsev_fd(struct tlsev *t)
{
	return t->fd;
}

static long
tlsev_bio_read_cb(BIO *b, int oper, const char *data, size_t len, int argi,
    long argl, int ret, size_t *read_bytes)
{
	struct tlsev *t;

	if (oper != (BIO_CB_READ|BIO_CB_RETURN))
		return ret;

	t = (struct tlsev *)BIO_get_callback_arg(b);

	if (t != NULL) {
		xlog(LOG_DEBUG, NULL,
		    "%s: %lu/%lu bytes read/requested on fd %d",
		    __func__, *read_bytes, len, (t == NULL) ? -1 : t->fd);

		t->tlswant = (len - *read_bytes < 1)
		    ? 1
		    : len - *read_bytes;
	}

	return ret;
}


static struct tlsev_peer *
tlsev_peer_tree_find(struct tlsev_listener *l, struct sockaddr *peer)
{
	struct tlsev_peer find;

	find.sa_family = peer->sa_family;
	if (find.sa_family == AF_INET)
		find.addr.v4.s_addr =
		    ((struct sockaddr_in *)peer)->sin_addr.s_addr;
	else
		memcpy(&find.addr.v6.s6_addr,
		    &((struct sockaddr_in6 *)peer)->sin6_addr.s6_addr,
		    sizeof(find.addr.v6.s6_addr));
	return RB_FIND(tlsev_peer_tree, &l->peer_tree, &find);
}

static int
tlsev_create(struct tlsev_listener *l, int fd, SSL_CTX *ctx,
    struct sockaddr *peer, socklen_t peerlen, struct xerr *e)
{
	struct tlsev      *t = NULL;
	struct tlsev_peer *p = NULL;

	if ((p = tlsev_peer_tree_find(l, peer)) != NULL) {
		if (p->count >= l->max_conn_per_ip) {
			return XERRF(e, XLOG_APP, XLOG_POLICY,
			    "client IP reached max allowed connections");
		}
		p->count++;
	}

	/* Need to set non-blocking so SSL_accept() does not block */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fcntl");
		goto fail;
	}

	if ((t = malloc(sizeof(struct tlsev))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	bzero(t, sizeof(struct tlsev));
	t->id = l->next_id++;
	t->fd = fd;
	t->listener = l;
	t->wpending = 0;
	bzero(&t->peer_addr, sizeof(t->peer_addr));
	memcpy(&t->peer_addr, peer, peerlen);
	t->peer_len = peerlen;

	if ((t->r = BIO_new(BIO_s_mem())) == NULL) {
		free(t);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto fail;
	}
	if ((t->w = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(t->r);
		free(t);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto fail;
	}

	if ((t->ssl = SSL_new(ctx)) == NULL) {
		BIO_free(t->w);
		BIO_free(t->r);
		free(t);
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_new");
		goto fail;
	}
	if (l->tlsev_data_idx >= 0)
		SSL_set_ex_data(t->ssl, l->tlsev_data_idx, t);
	SSL_set_bio(t->ssl, t->r, t->w);
	SSL_set_accept_state(t->ssl);

	if (l->use_rcv_lowat) {
		BIO_set_callback_ex(t->r, &tlsev_bio_read_cb);
		BIO_set_callback_arg(t->r, (char *)t);
	} else
		t->rcvlowat = 0;

	clock_gettime(CLOCK_MONOTONIC, &t->last_used_at);

	if (p == NULL) {
		if ((p = malloc(sizeof(struct tlsev_peer))) == NULL) {
			tlsev_free(t);
			XERRF(e, XLOG_ERRNO, errno, "malloc");
			goto fail;
		}

		p->sa_family = t->peer_addr.sin6_family;
		if (p->sa_family == AF_INET)
			p->addr.v4.s_addr =
			    ((struct sockaddr_in *)peer)->sin_addr.s_addr;
		else
			memcpy(&p->addr.v6.s6_addr,
			    &((struct sockaddr_in6 *)peer)->sin6_addr.s6_addr,
			    sizeof(p->addr.v6.s6_addr));
		p->count = 1;
		RB_INSERT(tlsev_peer_tree, &l->peer_tree, p);
	}

	if (idxheap_insert(&l->tlsev_store, t) == -1) {
		tlsev_free(t);
		XERRF(e, XLOG_ERRNO, errno, "idxheap_insert");
		goto fail;
	}

	return 0;
fail:
	if (p != NULL) {
		if (--p->count == 0) {
			RB_REMOVE(tlsev_peer_tree, &l->peer_tree, p);
			free(p);
		}
	}
	return -1;
}

static int
tlsev_close(struct tlsev_listener *l, struct tlsev *t)
{
	int                r;
	struct tlsev_peer *p;

	if (l->in_cb_data_free != NULL && t->in_cb_data != NULL) {
		l->in_cb_data_free(t->in_cb_data);
		t->in_cb_data = NULL;
	}

	if ((struct tlsev *)idxheap_removek(&l->tlsev_store, t) != t)
		abort();

	if ((p = tlsev_peer_tree_find(l,
	    (struct sockaddr *)&t->peer_addr)) != NULL) {
		if (--p->count == 0) {
			RB_REMOVE(tlsev_peer_tree, &l->peer_tree, p);
			free(p);
		}
	} else {
		xlog(LOG_ERR, NULL, "tlsev_close: could not find peer "
		    "in tlsev_peer_tree for fd %d", t->fd);
	}

	xlog(LOG_INFO, NULL, "closing fd %d", t->fd);
	if ((r = close(t->fd)) == -1)
		xlog_strerror(LOG_ERR, errno, "close: %d", t->fd);
	if (t->retry_buf != NULL)
		free(t->retry_buf);
	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);
	tlsev_free(t);
	l->active_clients--;
	return r;
}

struct tlsev *
tlsev_get(struct tlsev_listener *l, int fd)
{
	struct tlsev key;
	key.fd = fd;
	return idxheap_lookup(&l->tlsev_store, &key);
}

static int
tlsev_in(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	ssize_t n;
	int     r;

	/*
	 * TLS 1.2 records are 16KB max + expansions up to 2KB.
	 * TLS 1.3 can go above this wih record size limit extension
	 * but let's keep it reasonable.
	 */
	char    buf[TLSEV_IO_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t->last_used_at);
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

	n = read(t->fd, buf, sizeof(buf));
	if (n == -1)
		return XERRF(e, XLOG_ERRNO, errno, "read");
	else if (n == 0)
		return XERRF(e, XLOG_APP, XLOG_EOF, "read EOF");

	xlog(LOG_DEBUG, NULL, "%s: %d bytes read on fd %d", __func__, n, t->fd);

	if ((r = BIO_write(t->r, buf, n)) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");

	if (r < n)
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "BIO_write short write");

	if (!SSL_is_init_finished(t->ssl)) {
		if ((r = SSL_accept(t->ssl)) <= 0) {
			r = SSL_get_error(t->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_ZERO_RETURN:
				return 0;
			case SSL_ERROR_SSL:
				return XERRF(e, XLOG_SSL, r,
				    "SSL_accept: SSL_ERROR_SSL: %s",
				    ERR_error_string(r, NULL));
			default:
				return XERRF(e, XLOG_SSL, r, "SSL_accept: %s",
				    ERR_error_string(r, NULL));
			}
		}
		t->peer_cert = SSL_get_peer_certificate(t->ssl);
	}

	/*
	 * Normally this should be enough to empty the BIO_s_mem since we
	 * reuse the same buffer size as the raw bytes, minus the TLS
	 * overhead.
	 */
	if ((r = SSL_read(t->ssl, buf, sizeof(buf))) <= 0) {
		r = SSL_get_error(t->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_ZERO_RETURN:
			break;
		default:
			return XERRF(e, XLOG_SSL, r, "SSL_read: %s",
			    ERR_error_string(r, NULL));
		}
	} else if ((r = l->in_cb(t, buf, r, &t->in_cb_data)) == -1)
		return XERRF(e, XLOG_APP, XLOG_CALLBACK_ERR,
		    "t->in_cb_data failed");

	return 0;
}

static int
tlsev_out(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	ssize_t n;
	int     r, pending;
	char    buf[TLSEV_IO_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t->last_used_at);
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

	pending = BIO_pending(t->w);
	if (t->retry_buf != NULL) {
		n = write(t->fd, t->retry_buf_pos, t->retry_len);
		if (n != -1)
			xlog(LOG_DEBUG, NULL, "%s: wrote %d bytes on fd %d",
			    __func__, n, t->fd);
		if (n == -1) {
			return XERRF(e, XLOG_ERRNO, errno, "write");
		} else if (n < t->retry_len) {
			t->retry_len -= n;
			t->retry_buf_pos += n;
			return pending + t->retry_len;
		} else {
			t->retry_len = 0;
			free(t->retry_buf);
			t->retry_buf = NULL;
			t->retry_buf_pos = NULL;
		}
	}

	/*
	 * BIO_s_mem BIOs are not efficient with small reads followed by
	 * writes. It is best to attempt to completely drain it before any
	 * further writes happen.
	 */
	while (pending > 0) {
		r = BIO_read(t->w, buf, (pending > sizeof(buf))
		    ? sizeof(buf)
		    : pending);
		if (r <= 0)
			break;
		pending -= r;

		n = write(t->fd, buf, r);
		if (n != -1)
			xlog(LOG_DEBUG, NULL, "%s: wrote %d bytes on fd %d",
			    __func__, n, t->fd);
		if (n == -1) {
			return XERRF(e, XLOG_ERRNO, errno, "write");
		} else if (n < r) {
			/*
			 * On a short write, our TCP output buffer is likely
			 * full. Empty our BIO into retry_buf an try writing
			 * later.
			 */
			if ((t->retry_buf = malloc(pending + (r - n))) == NULL)
				return XERRF(e, XLOG_ERRNO, errno, "realloc");

			t->retry_buf_pos = t->retry_buf;
			memcpy(t->retry_buf, buf + n, r - n);
			t->retry_len = r - n;

			r = BIO_read(t->w, t->retry_buf + t->retry_len,
			    pending);
			if (r <= 0)
				break;
			t->retry_len += r;
			pending -= r;
			/*
			 * Normally at this point our t->w should be empty
			 * so we can break.
			 *
			 * If for some reason it is not empty, we don't want
			 * to loop and do another BIO_read so stop here anyway.
			 *
			 * This should never happen with BIO_s_mem but just
			 * in case.
			 */
			break;
		}
	}

	return pending + t->retry_len;
}

int
tlsev_reply(struct tlsev *t, const char *buf, int len)
{
	int                r;
#ifndef __OpenBSD__
	struct epoll_event ev;
#endif
	if ((r = SSL_write(t->ssl, buf, len)) <= 0) {
		xlog(LOG_ERR, NULL, "%s: SSL_write: %s", __func__,
		    ERR_error_string(SSL_get_error(t->ssl, r), NULL));
		return -1;
	}

	if (t->wpending == 0) {
#ifdef __OpenBSD__
		if (kq_ev_set(t->listener, t->fd, EVFILT_WRITE, EV_ADD) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			tlsev_close(t->listener, t);
			return -1;
		}
#else
		bzero(&ev, sizeof(ev));
		ev.data.fd = t->fd;
		ev.events = EPOLLIN|EPOLLOUT;
		if (epoll_ctl(t->listener->epollfd, EPOLL_CTL_MOD, t->fd, &ev) == -1) {
			xlog_strerror(LOG_ERR, errno, "epoll_ctl");
			tlsev_close(t->listener, t);
			return -1;
		}
#endif
	}
	if ((t->wpending = BIO_pending(t->w)) == -1) {
		xlog(LOG_ERR, NULL, "%s: SSL_write: %s", __func__,
		    ERR_error_string(SSL_get_error(t->ssl, r), NULL));
		return -1;
	}
	xlog(LOG_DEBUG, NULL, "%s: fd %d t->pending = %d", __func__, t->fd,
	    t->wpending);
	return t->wpending;
}

void
tlsev_drain(struct tlsev *t)
{
	t->drain = 1;
}

static int
tlsev_toggle_listen(struct tlsev_listener *l, int on)
{
	int i;
#ifndef __OpenBSD__
	struct epoll_event   ev;
#endif

#ifdef __OpenBSD__
	for (i = 0; i < l->lsock_len; i++)
		if (kq_ev_set(l, l->lsock[i], EVFILT_READ,
		    (on == 1) ? EV_ENABLE : EV_DISABLE) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			return -1;
		}
#else
	for (i = 0; i < l->lsock_len; i++) {
		bzero(&ev, sizeof(ev));
		ev.events = (on == 1) ? EPOLLIN|EPOLLEXCLUSIVE : EPOLLIN;
		ev.data.fd = l->lsock[i];
		if (epoll_ctl(l->epollfd,
		    (on == 1) ? EPOLL_CTL_ADD : EPOLL_CTL_DEL,
		    l->lsock[i], &ev) == -1) {
			xlog_strerror(LOG_ERR, errno, "epoll_ctl: lsock");
			return -1;
		}
	}
#endif
	return 0;
}

static int
tlsev_new_client(struct tlsev_listener *l, int fd,
    struct sockaddr *peer, socklen_t peerlen)
{
#ifndef __OpenBSD__
	struct epoll_event   ev;
#endif
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct xerr          e;

	if (getnameinfo(peer, peerlen, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
		xlog(LOG_INFO, NULL, "new connection from %s:%s", hbuf, sbuf);

	if (tlsev_create(l, fd, l->ctx, peer, peerlen, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, "tlsev_create");
		return -1;
	}

	if (l->accepting && ++l->active_clients >= l->max_clients) {
		xlog(LOG_WARNING, NULL, "max_clients reached (%d); "
		    "not accepting new connections", l->active_clients);
		l->accepting = 0;
		if (tlsev_toggle_listen(l, 0))
			l->shutdown_triggered = 1;
	}

#ifdef __OpenBSD__
	if (kq_ev_set(l, fd, EVFILT_READ, EV_ADD) == -1) {
		xlog_strerror(LOG_ERR, errno, "kq_ev_set");
		return -1;
	}
#else
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl");
		return -1;
	}
#endif
	return 0;
}

static int
tlsev_ev_read(struct tlsev_listener *l, struct tlsev *t)
{
	int         r;
	struct xerr e;
#ifndef __OpenBSD__
	struct epoll_event   ev;
#endif
	r = tlsev_in(l, t, xerrz(&e));
	if (r == -1) {
		if (xerr_is(&e, XLOG_APP, XLOG_CALLBACK_ERR)) {
			xlog(LOG_WARNING, &e, "fd=%d", t->fd);
			tlsev_close(l, t);
			return -1;
		} else if (!xerr_is(&e, XLOG_APP, XLOG_EOF)) {
			xlog(LOG_ERR, &e, "fd=%d", t->fd);
			tlsev_close(l, t);
			return -1;
		}
		/*
		 * Don't close just yet for EOF,
		 * check how many pending writes
		 * we have and drain if necessary.
		 */
		xlog(LOG_DEBUG, NULL,
		    "remote is shutting down on fd %d", t->fd);
	}

	if (t->tlswant != t->rcvlowat) {
		/*
		 * Most of the time a TLS record is limited to 2^14 bytes.
		 * We probably don't want to make our low watermark higher
		 * than this anyway.
		 */
		t->rcvlowat = (t->tlswant > (1<<14)) ? 1<<14 : t->tlswant;
		xlog(LOG_DEBUG, NULL, "%s: updating SO_RCVLOWAT to %d on fd %d",
		    __func__, t->rcvlowat, t->fd);
		if (setsockopt(t->fd, SOL_SOCKET, SO_RCVLOWAT,
		    &t->tlswant, sizeof(t->tlswant)) == -1)
			xlog_strerror(LOG_ERR, errno, "setsockopt: %d", t->fd);
	}

	/*
	 * Get how many bytes can be read from our
	 * outgoing (write) BIO. Normally this shouldn't
	 * increase after a read, unless we are
	 * processing an SSL handshake (SSL_accept).
	 */
	if ((t->wpending = BIO_pending(t->w)) == -1) {
		xlog(LOG_ERR, NULL, "BIO_pending "
		    "failed (%d) on write BIO for "
		    "fd=%d", ERR_get_error(), t->fd);
		tlsev_close(l, t);
		return -1;
	}

	if (t->wpending > 0) {
#ifdef __OpenBSD__
		if (kq_ev_set(l, t->fd, EVFILT_WRITE, EV_ADD) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			tlsev_close(l, t);
			return -1;
		}
#else
		bzero(&ev, sizeof(ev));
		ev.data.fd = t->fd;
		ev.events = EPOLLIN|EPOLLOUT;
		if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
		    t->fd, &ev) == -1) {
			xlog_strerror(LOG_ERR, errno, "epoll_ctl");
			tlsev_close(l, t);
			return -1;
		}
#endif
	}

	if (r == -1) {
		if (t->wpending > 0) {
			xlog(LOG_DEBUG, NULL, "remote is shutting down "
			    "but we have %d bytes pending on fd %d",
			    t->wpending, t->fd);
			tlsev_drain(t);
		} else
			tlsev_close(l, t);
	}
	return 0;
}

static int
tlsev_ev_write(struct tlsev_listener *l, struct tlsev *t)
{
	int         r;
	struct xerr e;
#ifndef __OpenBSD__
	struct epoll_event   ev;
#endif

	r = tlsev_out(l, t, xerrz(&e));
	if (r == -1) {
		xlog(LOG_ERR, &e, "write on fd %d", t->fd);
		tlsev_close(l, t);
		return -1;
	}
	t->wpending = r;
	xlog(LOG_DEBUG, NULL, "t->wpending=%d on fd %d", t->wpending, t->fd);

	if (r == 0) {
		/*
		 * If reads were paused because we
		 * had pending data, we can now
		 * resume them.
		 */
		if (t->reads_paused) {
			t->reads_paused = 0;
#ifdef __OpenBSD__
			if (kq_ev_set(l, t->fd, EVFILT_READ, EV_ADD) == -1) {
				xlog_strerror(LOG_ERR, errno, "kq_ev_set");
				tlsev_close(l, t);
				return -1;
			}
			xlog(LOG_DEBUG, NULL,
			    "reenabling reads on fd %d", t->fd);
#endif
		}
#ifdef __OpenBSD__
		if (kq_ev_set(l, t->fd, EVFILT_WRITE, EV_DELETE) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			tlsev_close(l, t);
			return -1;
		}
#else
		bzero(&ev, sizeof(ev));
		ev.data.fd = t->fd;
		ev.events = EPOLLIN;
		if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD, t->fd, &ev) == -1) {
			xlog_strerror(LOG_ERR, errno, "epoll_ctl");
			tlsev_close(l, t);
			return -1;
		}
#endif
		xlog(LOG_DEBUG, NULL, "no pending bytes; "
		    "disabling writes on fd %d (drain=%d)", t->fd, t->drain);
		if (t->drain)
			tlsev_close(l, t);
	} else {
		/*
		 * If after coming out of writing back to the client we still
		 * have buffered data that couldn't make it to the socket
		 * buffer, and reads weren't already blocked, block them now.
		 */
		if (!t->reads_paused) {
			t->reads_paused = 1;
#ifdef __OpenBSD__
			if (kq_ev_set(l, t->fd, EVFILT_READ, EV_DELETE) == -1) {
				xlog_strerror(LOG_ERR, errno, "kq_ev_set");
				tlsev_close(l, t);
				return -1;
			}
#else
			bzero(&ev, sizeof(ev));
			ev.data.fd = t->fd;
			ev.events = EPOLLOUT;
			if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
			    t->fd, &ev) == -1) {
				xlog_strerror(LOG_ERR, errno, "epoll_ctl");
				tlsev_close(l, t);
				return -1;
			}
#endif
			// TODO: count the times we
			// paused reads; then remove log
			xlog(LOG_DEBUG, NULL, "pausing reads for fd %d", t->fd);
		}
		/*
		 * Return an error so the caller knows not to further process
		 * this fd.
		 */
		return -1;
	}
	return 0;
}

int
tlsev_poll(struct tlsev_listener *l)
{
#define TLSEV_NONE   0x00
#define TLSEV_READ   0x01
#define TLSEV_WRITE  0x02
	uint8_t              evtype;
	int                  nev = 0;
	time_t               time_diff_ns;
#ifdef __OpenBSD__
	struct timespec      kev_timeout = {1, 0};
#endif
	int                  fd, evfd;
	int                  n, timeout;
	size_t               i;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	struct tlsev        *t;
	struct timespec      now;
	int                  cleanup, is_listen;

	if (!l->accepting && l->active_clients < l->max_clients) {
		xlog(LOG_NOTICE, NULL, "active_clients=%d; "
		    "accepting new connections", l->active_clients);
		l->accepting = 1;
		if (tlsev_toggle_listen(l, 1) == -1) {
			tlsev_toggle_listen(l, 0);
			l->shutdown_triggered = 1;
		}
	}

	if (nev == l->max_events && tlsev_grow_events_buffer(l) == -1)
		xlog_strerror(LOG_WARNING, errno, "pending events buffer "
		    "resize failed; current size  is %d", l->max_events);

#ifdef __OpenBSD__
	nev = kevent(l->kq, l->ch, l->chn, l->events, l->max_events,
	    &kev_timeout);
	l->chn = 0;
#else
	nev = epoll_wait(l->epollfd, l->events, l->max_events, 1000);
#endif

	if (nev == -1) {
		if (errno != EINTR) {
#ifdef __OpenBSD__
			xlog_strerror(LOG_ERR, errno, "kevent");
#else
			xlog_strerror(LOG_ERR, errno, "epoll_wait");
#endif
			return -1;
		}
		if (l->shutdown_triggered && l->lsock_len > 0) {
#ifndef __OpenBSD__
			if (l->accepting)
				tlsev_toggle_listen(l, 0);
#endif
			for (i = 0; i < l->lsock_len; i++)
				close(l->lsock[i]);
			l->lsock_len = 0;
		}
		return 0;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	time_diff_ns = ((now.tv_sec * 1000000000) + now.tv_nsec) -
	    ((l->last_purge.tv_sec * 1000000000) + l->last_purge.tv_nsec);
	if (time_diff_ns >= 1000000000) {
		l->last_purge.tv_sec = now.tv_sec;
		l->last_purge.tv_nsec = now.tv_nsec;

		timeout = l->socket_timeout_max -
		    ((l->socket_timeout_max - l->socket_timeout_min) *
		     l->active_clients / l->max_clients);

		t = idxheap_peek(&l->tlsev_store, 0);
		while (t != NULL) {
			if (now.tv_sec < t->last_used_at.tv_sec + timeout ||
			    (now.tv_sec == t->last_used_at.tv_sec + timeout &&
			     now.tv_nsec <= t->last_used_at.tv_nsec))
				break;
			xlog(LOG_NOTICE, NULL, "timeout reached for "
			    "fd %d after %ds; closing socket", t->fd,
			    now.tv_sec - t->last_used_at.tv_sec);
			tlsev_close(l, t);
			t = idxheap_peek(&l->tlsev_store, 0);
		}
	}

	for (n = 0; n < nev; n++) {
#ifdef __OpenBSD__
		evfd = l->events[n].ident;
#else
		evfd = l->events[n].data.fd;
#endif
		is_listen = 0;
		for (i = 0; i < l->lsock_len; i++) {
			if (evfd == l->lsock[i]) {
				is_listen = 1;
				break;
			}
		}
		if (is_listen) {
			if ((fd = accept(evfd, (struct sockaddr *)&peer,
			    &peerlen)) == -1) {
				if (errno == EINTR)
					continue;

				if (errno == EWOULDBLOCK) {
					if (nev == 1)
						// TODO: track how many times
						// we unblock just for an
						// accept() we didn't handle
						;
					continue;
				}
				xlog_strerror(LOG_ERR, errno, "accept");
				continue;
			}

			if (tlsev_new_client(l, fd, (struct sockaddr *)&peer,
			    peerlen) == -1)
				close(fd);
			continue;
		}

		t = tlsev_get(l, evfd);
		if (t == NULL) {
			cleanup = 1;
			for (i = 0; i < l->fd_callbacks_used; i++) {
				if (l->fd_callbacks[i].fd != evfd)
					continue;

				/* Descriptor is valid, don't remove */
				cleanup = 0;
				if (l->fd_callbacks[i].cb(evfd) <= 0)
					tlsev_del_fd_cb(l, i);
			}

			if (!cleanup)
				continue;

			xlog(LOG_ERR, NULL,
			    "tlsev_get on fd %d not found", evfd);

			if (close(evfd) == -1)
				xlog_strerror(LOG_ERR, errno, "close");
			else
				l->active_clients--;
			continue;
		}

		evtype = TLSEV_NONE;
#ifdef __OpenBSD__
		if (l->events[n].filter == EVFILT_READ)
			evtype = TLSEV_READ;
		else if (l->events[n].filter == EVFILT_WRITE)
			evtype = TLSEV_WRITE;
#else
		if (l->events[n].events & EPOLLERR)
			/* Not sure when this happens */
			xlog(LOG_WARNING, NULL, "EPOLLERR: fd=%d", t->fd);
		if (l->events[n].events & EPOLLIN)
			evtype |= TLSEV_READ;
		if (l->events[n].events & EPOLLOUT)
			evtype |= TLSEV_WRITE;
#endif
		/*
		 * We process writes before reads to keep our
		 * buffers small if possible.
		 */
		if (evtype & TLSEV_WRITE) {
			/*
			 * If tlsev_ev_write() returns -1, either
			 * there was an issue with the socket or we
			 * paused reads and should skip them.
			 */
			if (tlsev_ev_write(l, t) == -1)
				continue;
		}

		if (evtype & TLSEV_READ)
			tlsev_ev_read(l, t);
	}
	return 0;
}

int
tlsev_run(struct tlsev_listener *l)
{
	clock_gettime(CLOCK_MONOTONIC, &l->last_purge);
	while (!l->shutdown_triggered || l->active_clients > 0) {
		if (tlsev_poll(l) == -1)
			return -1;
	}
	return 0;
}

void
tlsev_shutdown(struct tlsev_listener *l)
{
	l->shutdown_triggered = 1;
}
