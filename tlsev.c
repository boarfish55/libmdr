/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/types.h>
#ifndef __linux__
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
#include <mdr/tlsev.h>
#include <mdr/idxheap.h>

static int tlsev_data_idx = -1;

static int      tlsev_peer_tree_cmp(struct tlsev_peer *, struct tlsev_peer *);
static int      tlsev_timeout_cmp(const void *, const void *);
static int      tlsev_match(const void *, const void *);
static uint32_t tlsev_hash(const void *);
static int      tlsev_grow_events_buffer(struct tlsev_listener *);
static int      bio_pending_x(BIO *);
#ifndef __linux__
static int      kq_ev_set(struct tlsev_listener *, int, short, u_short);
#endif
static long     tlsev_bio_read_cb(BIO *, int, const char *, size_t, int,
                    long, int, size_t *);
static int      tlsev_close(struct tlsev *);
static int      tlsev_in(struct tlsev_listener *, struct tlsev *,
                    struct xerr *);
static int      tlsev_out(struct tlsev_listener *, struct tlsev *,
                    struct xerr *);
static int      tlsev_toggle_listen(struct tlsev_listener *, int);
static int      tlsev_new_client(struct tlsev_listener *, int,
                    struct sockaddr *, socklen_t);
static int      tlsev_ev_read(struct tlsev_listener *, struct tlsev *);
static int      tlsev_ev_write(struct tlsev_listener *, struct tlsev *);

static struct tlsev_peer *tlsev_peer_tree_find(struct tlsev_listener *,
                              struct sockaddr *);
static struct tlsev      *tlsev_create(struct tlsev_listener *, int, SSL_CTX *,
                              struct sockaddr *, socklen_t, struct xerr *);

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

static int
tlsev_grow_events_buffer(struct tlsev_listener *l)
{
	void *tmp;
	int   new_max = l->max_events + 1000;

#ifndef __linux__
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

static int
bio_pending_x(BIO *b)
{
	int r = BIO_pending(b);
	/*
	 * For BIO_s_mem(3), BIO_pending returning an error would normally
	 * indicate an programming error.
	 */
	if (r < 0)
		abort();
	return r;
}

#ifndef __linux__
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
		    __func__, *read_bytes, len, t->fd);

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

static struct tlsev *
tlsev_create(struct tlsev_listener *l, int fd, SSL_CTX *ctx,
    struct sockaddr *peer, socklen_t peerlen, struct xerr *e)
{
	struct tlsev      *t = NULL;
	struct tlsev_peer *p = NULL;

	if ((p = tlsev_peer_tree_find(l, peer)) != NULL) {
		if (p->count >= l->max_conn_per_ip) {
			XERRF(e, XLOG_APP, XLOG_LIMITED,
			    "client IP reached max allowed connections");
			return NULL;
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
	bzero(&t->peer_addr, sizeof(t->peer_addr));
	memcpy(&t->peer_addr, peer, peerlen);
	t->peer_len = peerlen;

	if ((t->r = BIO_new(BIO_s_mem())) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto fail;
	}
	if ((t->w = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(t->r);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto fail;
	}

	if ((t->ssl = SSL_new(ctx)) == NULL) {
		BIO_free(t->w);
		BIO_free(t->r);
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_new");
		goto fail;
	}
	SSL_set_ex_data(t->ssl, tlsev_data_idx, t);
	/*
	 * Once we assign the BIOs to our SSL object, ownership is transferred
	 * and SSL_free() will take care of freeing them.
	 */
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
		XERRF(e, XLOG_ERRNO, errno, "idxheap_insert");
		goto fail;
	}

	return t;
fail:
	if (p != NULL) {
		if (--p->count == 0) {
			RB_REMOVE(tlsev_peer_tree, &l->peer_tree, p);
			free(p);
		}
	}
	if (t->ssl != NULL)
		SSL_free(t->ssl);
	free(t);
	return NULL;
}

static int
tlsev_close(struct tlsev *t)
{
	int                r;
	struct tlsev_peer *p;

	if (t->listener->client_cb_data_free != NULL &&
	    t->client_cb_data != NULL) {
		t->listener->client_cb_data_free(t, t->client_cb_data);
		t->client_cb_data = NULL;
	}

	if ((struct tlsev *)idxheap_removek(&t->listener->tlsev_store, t) != t)
		abort();

	if ((p = tlsev_peer_tree_find(t->listener,
	    (struct sockaddr *)&t->peer_addr)) != NULL) {
		if (--p->count == 0) {
			RB_REMOVE(tlsev_peer_tree, &t->listener->peer_tree, p);
			free(p);
		}
	} else {
		xlog(LOG_ERR, NULL, "tlsev_close: could not find peer "
		    "in tlsev_peer_tree for fd %d", t->fd);
	}

	xlog(LOG_DEBUG, NULL, "closing fd %d", t->fd);
	t->listener->active_clients--;
	if ((r = close(t->fd)) == -1)
		xlog_strerror(LOG_ERR, errno, "close: %d", t->fd);
	if (t->retry_buf != NULL)
		free(t->retry_buf);
	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);
	SSL_free(t->ssl);
	free(t);
	return r;
}

static int
tlsev_in(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	int  r;
	/*
	 * TLS 1.2 records are 16KB max + expansions up to 2KB.
	 * TLS 1.3 can go above this wih record size limit extension
	 * but let's keep it reasonable.
	 */
	char buf[TLSEV_IO_SIZE];

	clock_gettime(CLOCK_MONOTONIC, &t->last_used_at);
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

again:
	if ((r = read(t->fd, buf, sizeof(buf))) == -1) {
		if (errno == EINTR)
			goto again;
		return XERRF(e, XLOG_ERRNO, errno, "read");
	} else if (r == 0)
		return XERRF(e, XLOG_APP, XLOG_EOF, "read EOF");

	l->counters.raw_bytes_in += r;
	xlog(LOG_DEBUG, NULL, "%s: %d bytes read on fd %d",
	    __func__, r, t->fd);

	/*
	 * Writes to a BIO_s_mem will write the entire data or fail on
	 * malloc. Short writes will never occur.
	 */
	if (BIO_write(t->r, buf, r) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");

	if (!SSL_is_init_finished(t->ssl)) {
		if ((r = SSL_accept(t->ssl)) <= 0) {
			r = SSL_get_error(t->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_ZERO_RETURN:
				return 0;
			case SSL_ERROR_SYSCALL:
				return XERRF(e, XLOG_ERRNO,
				    errno, "SSL_accept");
			case SSL_ERROR_SSL:
				return XERRF(e, XLOG_SSL, ERR_get_error(),
				    "SSL_accept");
			default:
				return XERRF(e, XLOG_APP, XLOG_FAIL,
				    "SSL_accept unhandled error");
			}
		}
		t->peer_cert = SSL_get_peer_certificate(t->ssl);
	}

	/*
	 * Normally the same buffer we used for the raw bytes should be
	 * large enough to drain the underlying BIO_s_mem, since we
	 * don't have the TLS overhead.
	 */
	do {
		/*
		 * SSL_read will only process a single TLS record. The next
		 * record in the read BIO will only be processed if SSL_read
		 * needs to fetch more bytes. So it's important to loop on
		 * BIO_pending() in addition to SSL_pending() below, since
		 * SSL_pending() will not report unprocessed bytes, so we
		 * could end up with full unprocessed records in the BIO but
		 * ignore them. LibreSSL does not have SSL_has_pending() hence
		 * why we do BIO_pending() instead in addition.
		 */
		if ((r = SSL_read(t->ssl, buf, sizeof(buf))) <= 0) {
			r = SSL_get_error(t->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				// TODO: do we need to make sure writes are
				// enabled here, or will BIO_pending do the
				// trick elsewhere?
			case SSL_ERROR_ZERO_RETURN:
				return 0;
			default:
				return XERRF(e, XLOG_SSL, r, "SSL_read");
			}
		}
		l->counters.ssl_bytes_in += r;
		if (l->client_msg_in_cb(t, buf, r, &t->client_cb_data) == -1) {
			return XERRF(e, XLOG_APP, XLOG_CALLBACK_ERR,
			    "t->client_cb_data failed");
		}
	} while (SSL_pending(t->ssl) > 0 || BIO_pending(t->r));

	return 0;
}

/*
 * Returns 0 on success, -1 on error.
 */
static int
tlsev_out(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	ssize_t  r;
	int      pending;
	char    *bio_data;

	clock_gettime(CLOCK_MONOTONIC, &t->last_used_at);
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

	/*
	 * If we had any pending bytes in our retry_buf, try to
	 * send them now before we pull more from our read BIO.
	 */
	if (t->retry_buf != NULL) {
again:
		r = write(t->fd, t->retry_buf_pos, t->retry_len);
		if (r == -1) {
			if (errno == EAGAIN)
				return 0;
			if (errno == EINTR)
				goto again;
			return XERRF(e, XLOG_ERRNO, errno, "write");
		}

		xlog(LOG_DEBUG, NULL, "%s: wrote %ld bytes on fd %d",
		    __func__, r, t->fd);

		l->counters.raw_bytes_out += r;

		if (r < t->retry_len) {
			t->retry_len -= r;
			t->retry_buf_pos += r;
			/*
			 * Return immediately if we weren't even able
			 * to send all our retry_buf; no sense in trying
			 * to get more bytes from our read BIO.
			 */
			return 0;
		} else {
			t->retry_len = 0;
			free(t->retry_buf);
			t->retry_buf = NULL;
			t->retry_buf_pos = NULL;
		}
	}

	/*
	 * BIO_s_mem BIOs are not efficient with small reads followed by
	 * writes. It is best to completely drain it before any further
	 * writes happen to it and thus cause needless memory copies.
	 *
	 * We borrow a pointer to the BIO's data so we can "peek" and
	 * send as much as we can. Any remaining data we'll read out
	 * and store in our retry_buf.
	 */
	if ((pending = BIO_get_mem_data(t->w, &bio_data)) < 0)
		return XERRF(e, XLOG_APP, XLOG_FAIL,
		    "BIO_get_mem_data() unexpectedly returned %d", pending);

	/*
	 * Both t->w and retry_buf have been drained.
	 */
	if (pending == 0)
		return 0;
again2:
	r = write(t->fd, bio_data, pending);
	if (r == -1) {
		if (errno == EAGAIN)
			return 0;
		if (errno == EINTR)
			goto again2;
		return XERRF(e, XLOG_ERRNO, errno, "write");
	}

	xlog(LOG_DEBUG, NULL, "%s: wrote %ld bytes on fd %d",
	    __func__, r, t->fd);

	l->counters.raw_bytes_out += r;

	if (r < pending) {
		/*
		 * On a short write, our TCP output buffer is likely
		 * full. Save the remaining bytes into retry_buf
		 * and try again later.
		 */
		pending -= r;
		if ((t->retry_buf = malloc(pending)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "malloc");

		t->retry_buf_pos = t->retry_buf;
		memcpy(t->retry_buf, bio_data + r, pending);
		t->retry_len = pending;
	}

	/*
	 * BIO_reset() is faster than BIO_read() as it does a memset()
	 * instead of memcpy() on the internal buffer. In both cases,
	 * subsequent writes to the BIO will not need to move data to
	 * the start of the buffer.
	 */
	BIO_reset(t->w);
	return 0;
}

static int
tlsev_toggle_listen(struct tlsev_listener *l, int on)
{
	int i;
#ifdef __linux__
	struct epoll_event   ev;
#endif

#ifdef __linux__
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
#else
	for (i = 0; i < l->lsock_len; i++)
		if (kq_ev_set(l, l->lsock[i], EVFILT_READ,
		    (on == 1) ? EV_ENABLE : EV_DISABLE) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			return -1;
		}
#endif
	return 0;
}

static int
tlsev_new_client(struct tlsev_listener *l, int fd,
    struct sockaddr *peer, socklen_t peerlen)
{
#ifdef __linux__
	struct epoll_event  ev;
#endif
	char                hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct xerr         e;
	struct tlsev       *t;
	struct tlsev_peer  *p;

	if (getnameinfo(peer, peerlen, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
		xlog(LOG_INFO, NULL, "new connection from %s:%s (fd %d)",
		    hbuf, sbuf, fd);

	if ((t = tlsev_create(l, fd, l->ctx, peer, peerlen,
	    xerrz(&e))) == NULL) {
		xlog(LOG_ERR, &e, "tlsev_create");
		return -1;
	}
#ifdef __linux__
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl");
		goto fail;
	}
#else
	if (kq_ev_set(l, fd, EVFILT_READ, EV_ADD) == -1) {
		xlog_strerror(LOG_ERR, errno, "kq_ev_set");
		goto fail;
	}
#endif
	if (l->accepting) {
		l->counters.client_accepts++;
		if (++l->active_clients >= l->max_clients) {
			l->counters.max_clients_reached++;
			xlog(LOG_WARNING, NULL, "max_clients reached (%d); "
			    "not accepting new connections", l->active_clients);
			l->accepting = 0;
			if (tlsev_toggle_listen(l, 0))
				l->shutdown_triggered = 1;
		}
	}
	return 0;
fail:
	if ((struct tlsev *)idxheap_removek(&l->tlsev_store, t) != t)
		abort();
	if ((p = tlsev_peer_tree_find(l,
	    (struct sockaddr *)&t->peer_addr)) != NULL) {
		if (--p->count == 0) {
			RB_REMOVE(tlsev_peer_tree, &l->peer_tree, p);
			free(p);
		}
	}
	free(t->ssl);
	free(t);
	return -1;
}

static int
tlsev_ev_read(struct tlsev_listener *l, struct tlsev *t)
{
	int         r;
	struct xerr e;
#ifdef __linux__
	struct epoll_event   ev;
#endif
	if ((r = tlsev_in(l, t, xerrz(&e))) == -1) {
		if (xerr_is(&e, XLOG_APP, XLOG_CALLBACK_ERR)) {
			xlog(LOG_WARNING, &e, "fd=%d", t->fd);
			tlsev_close(t);
			return -1;
		} else if (!xerr_is(&e, XLOG_APP, XLOG_EOF)) {
			xlog(LOG_ERR, &e, "fd=%d", t->fd);
			tlsev_close(t);
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
		    &t->rcvlowat, sizeof(t->rcvlowat)) == -1)
			xlog_strerror(LOG_ERR, errno, "setsockopt: %d", t->fd);
	}

	/*
	 * If we processed an SSL handshake in tlsev_in() above, we may
	 * have bytes to send out, so start polling for write.
	 */
	if (tlsev_outbufsz(t) > 0) {
#ifdef __linux__
		bzero(&ev, sizeof(ev));
		ev.data.fd = t->fd;
		ev.events = EPOLLIN|EPOLLOUT;
		if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
		    t->fd, &ev) == -1) {
			xlog_strerror(LOG_ERR, errno, "epoll_ctl");
			tlsev_close(t);
			return -1;
		}
#else
		if (kq_ev_set(l, t->fd, EVFILT_WRITE, EV_ADD) == -1) {
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			tlsev_close(t);
			return -1;
		}
#endif
	}

	if (r == -1) {
		if (tlsev_outbufsz(t) > 0) {
			xlog(LOG_DEBUG, NULL, "%s: remote is shutting down "
			    "but we have %ld bytes to send on fd %d",
			    __func__, tlsev_outbufsz(t), t->fd);
			tlsev_drain(t);
		} else
			tlsev_close(t);
	}
	return 0;
}

static int
tlsev_ev_write(struct tlsev_listener *l, struct tlsev *t)
{
	struct xerr e;
#ifdef __linux__
	struct epoll_event   ev;
#endif
	if (tlsev_out(l, t, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, "write on fd %d", t->fd);
		tlsev_close(t);
		return -1;
	}

	xlog(LOG_DEBUG, NULL, "outbufsz=%ld on fd %d",
	    tlsev_outbufsz(t), t->fd);

	/*
	 * We have no more bytes to send; consider stopping polling
	 * for writes.
	 */
	if (tlsev_outbufsz(t) == 0) {
		if (t->drain) {
			tlsev_close(t);
		} else {
			xlog(LOG_DEBUG, NULL, "no pending bytes; "
			    "disabling writes on fd %d", t->fd);
#ifdef __linux__
			bzero(&ev, sizeof(ev));
			ev.data.fd = t->fd;
			ev.events = EPOLLIN;
			if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD, t->fd, &ev) == -1) {
				xlog_strerror(LOG_ERR, errno, "epoll_ctl");
				tlsev_close(t);
				return -1;
			}
#else
			if (kq_ev_set(l, t->fd, EVFILT_WRITE, EV_DELETE) == -1) {
				xlog_strerror(LOG_ERR, errno, "kq_ev_set");
				tlsev_close(t);
				return -1;
			}
#endif
			if (t->reads_paused) {
				/*
				 * If reads were paused because we had pending
				 * data, we can now resume them since we have
				 * nothing else to send.
				 */
				t->reads_paused = 0;
#ifndef __linux__
				if (kq_ev_set(l, t->fd, EVFILT_READ,
				    EV_ADD) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "kq_ev_set");
					tlsev_close(l, t);
					return -1;
				}
				xlog(LOG_DEBUG, NULL,
				    "reenabling reads on fd %d", t->fd);
#endif
			}
		}
	} else {
		/*
		 * If after coming out of writing back to the client we still
		 * have buffered data that couldn't make it to the socket
		 * buffer, and reads weren't already blocked, block them now.
		 * In other words, don't drain the incoming TCP buffer to
		 * send pressure back to the client.
		 */
		if (!t->reads_paused) {
			t->reads_paused = 1;
#ifdef __linux__
			bzero(&ev, sizeof(ev));
			ev.data.fd = t->fd;
			ev.events = EPOLLOUT;
			if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
			    t->fd, &ev) == -1) {
				xlog_strerror(LOG_ERR, errno, "epoll_ctl");
				tlsev_close(t);
				return -1;
			}
#else
			if (kq_ev_set(l, t->fd, EVFILT_READ, EV_DELETE) == -1) {
				xlog_strerror(LOG_ERR, errno, "kq_ev_set");
				tlsev_close(t);
				return -1;
			}
#endif
			l->counters.read_pauses++;
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
tlsev_init(struct tlsev_listener *l, int *lsock, size_t lsock_len,
    uint32_t max_clients, SSL_CTX *ctx,
    int (*client_msg_in_cb)(struct tlsev *, const char *, size_t, void **),
    void (*client_cb_data_free)(struct tlsev *, void *))
{
	int                n;
#ifndef __linux__
	struct kevent      ch[lsock_len];
#else
	struct epoll_event ev;
#endif
	if (client_msg_in_cb == NULL || l == NULL || ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (tlsev_data_idx == -1) {
		errno = 0;
		tlsev_data_idx = SSL_get_ex_new_index(0, "tlsev_idx",
		    NULL, NULL, NULL);
		if (tlsev_data_idx == -1) {
			return -1;
		}
	}

	bzero(l, sizeof(struct tlsev_listener));
	l->ctx = ctx;
	l->lsock_len = lsock_len;
	l->socket_timeout_min = 0;
	l->socket_timeout_max = 0;
	l->next_id = 1;
	l->client_msg_in_cb = client_msg_in_cb;
	l->client_cb_data_free = client_cb_data_free;

	if (max_clients < 1)
		max_clients = 1;
	if (max_clients > TLSEV_MAX_CLIENTS)
		max_clients = TLSEV_MAX_CLIENTS;
	l->max_clients = max_clients;
	l->max_conn_per_ip = UINT16_MAX;
	l->use_rcv_lowat = 1;
	l->accepting = 1;

	for (n = 0; n < lsock_len; n++)
		if (fcntl(lsock[n], F_SETFL, O_NONBLOCK) == -1)
			return -1;

	if (idxheap_init(&l->tlsev_store,
	    (l->max_clients / 2 < 1) ? 2 : l->max_clients / 2,
	    &tlsev_timeout_cmp, &tlsev_match,
	    (void(*)(void *))&tlsev_close, &tlsev_hash))
		return -1;

	RB_INIT(&l->peer_tree);
	l->lsock = reallocarray(NULL, sizeof(int), l->lsock_len);
	if (l->lsock == NULL) {
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	memcpy(l->lsock, lsock, sizeof(int) * l->lsock_len);
#ifndef __linux__
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

int
tlsev_set_socket_timeouts(struct tlsev_listener *l, int min, int max)
{
	if (l == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (min < 0 || max < 0 || max < min) {
		errno = EINVAL;
		return -1;
	}

	l->socket_timeout_min = min;
	l->socket_timeout_max = max;

	return 0;
}

int
tlsev_set_max_conns_per_ip(struct tlsev_listener *l, uint16_t n)
{
	if (l == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (n < 1) {
		errno = EINVAL;
		return -1;
	}

	l->max_conn_per_ip = n;

	return 0;
}

size_t
tlsev_outbufsz(struct tlsev *t)
{
	size_t pending = bio_pending_x(t->w);
	return pending + t->retry_len;
}

int
tlsev_auto_rcv_lowat(struct tlsev_listener *l, int on)
{
	if (l == NULL) {
		errno = EINVAL;
		return -1;
	}

	l->use_rcv_lowat = on;
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
#ifndef __linux__
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
#ifndef __linux__
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
#ifndef __linux__
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

struct tlsev *
tlsev_get(struct tlsev_listener *l, int fd)
{
	struct tlsev key;
	key.fd = fd;
	return idxheap_lookup(&l->tlsev_store, &key);
}

struct tlsev *
tlsev_get_by_ctx(X509_STORE_CTX *ctx)
{
	SSL *ssl;

	ssl = X509_STORE_CTX_get_ex_data(ctx,
	    SSL_get_ex_data_X509_STORE_CTX_idx());
	return (struct tlsev *)SSL_get_ex_data(ssl, tlsev_data_idx);
}

int
tlsev_reply(struct tlsev *t, const unsigned char *buf, int len)
{
	int                r, writes_on = (tlsev_outbufsz(t) > 0);
#ifdef __linux__
	struct epoll_event ev;
#endif
	errno = 0;
	if ((r = SSL_write(t->ssl, buf, len)) <= 0) {
		xlog(LOG_ERR, NULL, "%s: SSL_write: %s", __func__,
		    ERR_error_string(SSL_get_error(t->ssl, r), NULL));
		/*
		 * Per SSL_write, either we have more than INT_MAX buffered, or
		 * malloc failure. Latter is more likely.
		 */
		if (((size_t)bio_pending_x(t->w) + len) > INT_MAX)
			errno = EOVERFLOW;
		else
			errno = ENOMEM;
		return -1;
	}

	t->listener->counters.ssl_bytes_out += r;

	/*
	 * Start polling for write if we previously had no pending writes,
	 * meaning polling would have been turned off...
	 */
	if (!writes_on) {
#ifdef __linux__
		bzero(&ev, sizeof(ev));
		ev.data.fd = t->fd;
		ev.events = EPOLLIN|EPOLLOUT;
		if (epoll_ctl(t->listener->epollfd, EPOLL_CTL_MOD, t->fd,
		    &ev) == -1) {
			errno = EIO;
			xlog_strerror(LOG_ERR, errno, "epoll_ctl");
			tlsev_close(t);
			return -1;
		}
#else
		if (kq_ev_set(t->listener, t->fd, EVFILT_WRITE, EV_ADD) == -1) {
			errno = EIO;
			xlog_strerror(LOG_ERR, errno, "kq_ev_set");
			tlsev_close(t);
			return -1;
		}
#endif
	}
	/*
	 * Then update wpending with the new amount of raw bytes pending.
	 */
	xlog(LOG_DEBUG, NULL, "%s: fd %d outbufsz=%ld", __func__,
	    t->fd, tlsev_outbufsz(t));
	return tlsev_outbufsz(t);
}

void
tlsev_drain(struct tlsev *t)
{
	t->drain = 1;
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
#ifndef __linux__
	struct timespec      kev_timeout = {1, 0};
#endif
	int                  fd, evfd;
	int                  n, timeout;
	size_t               i;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	struct tlsev        *t;
	struct timespec      now;
	int                  is_listen;

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

#ifdef __linux__
	nev = epoll_wait(l->epollfd, l->events, l->max_events, 1000);
#else
	nev = kevent(l->kq, l->ch, l->chn, l->events, l->max_events,
	    &kev_timeout);
	l->chn = 0;
#endif

	if (nev == -1) {
		if (errno != EINTR) {
#ifdef __linux__
			xlog_strerror(LOG_ERR, errno, "epoll_wait");
#else
			xlog_strerror(LOG_ERR, errno, "kevent");
#endif
			return -1;
		}
		if (l->shutdown_triggered && l->lsock_len > 0) {
#ifdef __linux__
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
			l->counters.session_timeouts++;
			xlog(LOG_NOTICE, NULL, "timeout reached for "
			    "fd %d after %lds; closing socket", t->fd,
			    now.tv_sec - t->last_used_at.tv_sec);
			tlsev_close(t);
			t = idxheap_peek(&l->tlsev_store, 0);
		}
	}

	for (n = 0; n < nev; n++) {
#ifdef __linux__
		evfd = l->events[n].data.fd;
#else
		evfd = l->events[n].ident;
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
					if (nev == 1) {
						/*
						 * Track how many times we
						 * wake up just for an accept()
						 * we didn't handle.
						 */
						l->counters.wasted_accepts++;
					}
					continue;
				}
				if (errno == EMFILE) {
					if (l->active_clients < 1)
						l->max_clients = 1;
					else
						l->max_clients =
						    l->active_clients;
					xlog_strerror(LOG_ERR, errno,
					    "fd limit reached; dropping "
					    "max_clients to %d",
					    l->max_clients);
					l->counters.file_ulimit_hits++;
					continue;
				} else if (errno == ENFILE) {
					/*
					 * We use LOG_DEBUG because this
					 * could be very noisy over syslog.
					 */
					xlog_strerror(LOG_DEBUG, errno,
					    "system fd limit reached; "
					    "active_clients is %d",
					    l->active_clients);
					l->counters.sys_ulimit_hits++;
				} else if (errno == ECONNABORTED) {
					l->counters.accept_conn_aborted++;
				} else {
					xlog_strerror(LOG_ERR, errno, "accept");
				}
				continue;
			}

			if (tlsev_new_client(l, fd, (struct sockaddr *)&peer,
			    peerlen) == -1)
				close(fd);
			continue;
		}

		evtype = TLSEV_NONE;
#ifdef __linux__
		if (l->events[n].events & EPOLLIN)
			evtype |= TLSEV_READ;
		if (l->events[n].events & EPOLLOUT)
			evtype |= TLSEV_WRITE;
#else
		if (l->events[n].filter == EVFILT_READ)
			evtype = TLSEV_READ;
		else if (l->events[n].filter == EVFILT_WRITE)
			evtype = TLSEV_WRITE;
#endif
		t = tlsev_get(l, evfd);
		if (t == NULL) {
			/*
			 * If the descriptor is not for one of our TLS clients,
			 * then it is one of our custom handlers. Clean it
			 * using the apropriate callback.
			 */
			for (i = 0; i < l->fd_callbacks_used; i++) {
				if (l->fd_callbacks[i].fd != evfd)
					continue;

				if (l->fd_callbacks[i].cb(evfd) <= 0)
					tlsev_del_fd_cb(l, i);
			}
			continue;
		}

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


		if (evtype & TLSEV_READ) {
#ifdef __linux__
			if (evtype & TLSEV_WRITE) {
				/*
				 * If TLSEV_WRITE is set it's possible we closed
				 * our tlsev since then, so lookup again.
				 */
				t = tlsev_get(l, evfd);
				if (t == NULL)
					continue;
			}
#endif
			tlsev_ev_read(l, t);
		}
	}
	return 0;
}

int
tlsev_run(struct tlsev_listener *l,
    int(*tasks)(struct tlsev_listener *, void *), void *task_args)
{
	clock_gettime(CLOCK_MONOTONIC, &l->last_purge);
	while (!l->shutdown_triggered || l->active_clients > 0) {
		if (tlsev_poll(l) == -1)
			return -1;
		if (tasks != NULL && !tasks(l, task_args))
			return -1;
	}
	return 0;
}

void
tlsev_shutdown(struct tlsev_listener *l)
{
	l->shutdown_triggered = 1;
}

void
tlsev_dump_counters(struct tlsev_listener *l, struct tlsev_counters *c)
{
	l->counters.active_clients = l->active_clients;
	memcpy(c, &l->counters, sizeof(struct tlsev_counters));
	bzero(&l->counters, sizeof(struct tlsev_counters));
}
