/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/time.h>
#include <sys/tree.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mdr/mdr.h>
#include <mdr/mdrd.h>
#include <mdr/util.h>
#include <poll.h>

static int
session_cmp(struct mdrd_besession *s1, struct mdrd_besession *s2)
{
	return (s1->id < s2->id) ? -1 : s1->id > s2->id;
}

SPLAY_HEAD(session_tree, mdrd_besession) sessions = SPLAY_INITIALIZER(&sessions);
SPLAY_PROTOTYPE(session_tree, mdrd_besession, entries, session_cmp);
SPLAY_GENERATE(session_tree, mdrd_besession, entries, session_cmp);

static void
session_free(struct mdrd_besession *s)
{
	if (s == NULL)
		return;

	SPLAY_REMOVE(session_tree, &sessions, s);
	if (s->cert != NULL)
		X509_free(s->cert);
	if (s->data != NULL && s->free_data != NULL)
		s->free_data(s->data);
	free(s);
}

int
mdrd_purge_sessions(time_t age_seconds)
{
	struct timespec        now;
	struct mdrd_besession *s, *next;
	int                    purged = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	for (s = SPLAY_MIN(session_tree, &sessions); s != NULL; s = next) {
		next = SPLAY_NEXT(session_tree, &sessions, s);
		if (now.tv_sec - s->last_seen.tv_sec >= age_seconds) {
			session_free(s);
			purged++;
		}
	}
	return purged;
}

/*
 * We don't call the umdr/pmdr_init() functions here,
 * we leave the choice of buffer and flags to the caller.
 */
int
mdrd_unpack_beclose(struct umdr *m, uint64_t *id)
{
	struct umdr_vec uv[1];

	if (umdr_unpack(m, mdr_msg_mdrd_beclose, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;
	*id = uv[0].v.u64;

	return 0;
}

int
mdrd_unpack_bein(struct umdr *m, uint64_t *id, int *fd, struct sockaddr *peer,
    socklen_t *slen, struct umdr *msg, X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;
	const uint8_t       *peer_addr;
	size_t               peer_addr_sz;
	uint16_t             port;
	struct sockaddr_in6 *peer6;
	struct sockaddr_in  *peer4;
	struct umdr_vec      uv[6];

	if (id == NULL || fd == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (umdr_unpack(m, mdr_msg_mdrd_bein, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;

	*id = uv[0].v.u64;
	*fd = uv[1].v.i32;
	peer_addr = uv[2].v.b.bytes;
	peer_addr_sz = uv[2].v.b.sz;
	port = uv[3].v.u16;
	if (msg != NULL)
		umdr_copy(msg, &uv[4].v.m);
	p = uv[5].v.b.bytes;
	cert_len = uv[5].v.b.sz;

	if (peer != NULL && slen != NULL) {
		if (peer_addr_sz == 16) {
			peer6 = (struct sockaddr_in6 *)peer;
			if (*slen >= sizeof(struct sockaddr_in6)) {
				*slen = sizeof(struct sockaddr_in6);
				peer6->sin6_family = AF_INET6;
				peer6->sin6_port = htons(port);
				memcpy(peer6->sin6_addr.s6_addr, peer_addr,
				    sizeof(peer6->sin6_addr.s6_addr));
				/* We don't carry the following info */
				peer6->sin6_flowinfo = 0;
				peer6->sin6_scope_id = 0;
			}
		} else {
			peer4 = (struct sockaddr_in *)peer;
			if (*slen >= sizeof(struct sockaddr_in)) {
				*slen = sizeof(struct sockaddr_in);
				peer4->sin_family = AF_INET;
				peer4->sin_port = htons(port);
				memcpy(&peer4->sin_addr.s_addr, peer_addr,
				    sizeof(peer4->sin_addr.s_addr));
			}
		}
	}

	if (peer_cert != NULL) {
		if (cert_len == 0) {
			*peer_cert = NULL;
			return 0;
		}
		*peer_cert = d2i_X509(NULL, &p, cert_len);
		if (*peer_cert == NULL) {
			errno = EBADMSG;
			return MDR_FAIL;
		}
	}

	return 0;
}

int
mdrd_unpack_besesserr(struct umdr *m, uint64_t *id)
{
	struct umdr_vec uv[1];

	if (umdr_unpack(m, mdr_msg_mdrd_besesserr, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;
	*id = uv[0].v.u64;

	return 0;
}

int
mdrd_beout_error(const struct mdrd_besession *sess, uint32_t beout_flags,
    uint32_t errcode, const char *errdesc)
{
	struct pmdr     pm;
	char            pbuf[mdr_hdr_size(MDR_FNONE) + 4 + 8 + strlen(errdesc)];
	struct pmdr_vec pv[2];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U32;
	pv[0].v.u32 = errcode;
	pv[1].type = MDR_S;
	pv[1].v.s = errdesc;
	if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
		return -1;

	return mdrd_beout(sess, beout_flags, &pm);
}

int
mdrd_beout_ok(const struct mdrd_besession *sess, uint32_t beout_flags)
{
	struct pmdr pm;
	char        pbuf[mdr_hdr_size(MDR_FNONE)];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (pmdr_pack(&pm, mdr_msg_ok, NULL, 0) == MDR_FAIL)
		return -1;
	return mdrd_beout(sess, beout_flags, &pm);
}

int
mdrd_beout(const struct mdrd_besession *sess, uint32_t beout_flags,
    const struct pmdr *msg)
{
	struct pmdr     pm;
	struct pmdr_vec pv[4];
	char            pbuf[pmdr_size(msg) + mdr_hdr_size(MDR_FNONE) + 16];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = sess->id;
	pv[1].type = MDR_I32;
	pv[1].v.i32 = sess->fd;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = beout_flags;

	if (msg != NULL) {
		pv[3].type = MDR_M;
		pv[3].v.pmdr = msg;
		if (pmdr_pack(&pm, mdr_msg_mdrd_beout, pv,
		    PMDRVECLEN(pv)) == MDR_FAIL)
			return -1;
	} else {
		if (pmdr_pack(&pm, mdr_msg_mdrd_beout_empty, pv,
		    PMDRVECLEN(pv) - 1) == MDR_FAIL)
			return -1;
	}

	if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
		return -1;

	if (beout_flags & MDRD_BEOUT_FCLOSE)
		/* Override our const here, we own this internal field. */
		((struct mdrd_besession *)sess)->must_free = 1;

	return 0;
}

static ssize_t
mdrd_fill(void *buf, size_t sz, void *args)
{
	return read(0, buf, sz);
}

static int
elapsed_ms_since(struct timespec *ts)
{
	struct timespec now, elapsed;

	clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, ts, &elapsed);
	return (elapsed.tv_sec * 1000) + (elapsed.tv_nsec / 1000000);
}

ptrdiff_t
mdrd_recv(struct mdrd_recvhdl *mrh, int timeout_ms)
{
	int                    r;
	ptrdiff_t              c;
	struct pmdr            pm;
	char                   pbuf[64];
	struct pmdr_vec        pv[2];
	char                   errmsg[64];
	struct mdrd_besession *sess = NULL, needle, tmpsess;
	struct umdr            um;

	uint64_t               id;
	int                    fd;
	const struct uint8_t  *peer;
	size_t                 peer_sz;
	uint16_t               port;
	const uint8_t         *crt_bytes;
	size_t                 crt_len;

	struct sockaddr_in    *peer4;
	struct pollfd          pfd;
	struct timespec        start;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (mrh == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/*
	 * If the session in our previous call needs to be freed because
	 * we saw MDRD_BEOUT_FCLOSE set on a response, do it here.
	 */
	if (mrh->session != NULL) {
		if (mrh->session->must_free)
			session_free(mrh->session);
		mrh->session->must_free = 0;
		mrh->session = NULL;
	}
	mrh->msg = NULL;
again:
	pfd.fd = 0;
	pfd.events = POLLIN;
	pfd.revents = 0;
	r = poll(&pfd, 1, timeout_ms);

	if (r == -1) {
		if (errno != EINTR)
			return MDR_FAIL;

		timeout_ms -= elapsed_ms_since(&start);
		if (timeout_ms <= 0) {
			errno = ETIMEDOUT;
			return MDR_FAIL;
		}
		goto again;
	}

	if (r == 0) {
		errno = ETIMEDOUT;
		return MDR_FAIL;
	}

	if ((c = mdr_fill(mrh->buf, mrh->bufsz, &mrh->offset,
	    &mdrd_fill, NULL)) == -1) {
		if (errno != EAGAIN)
			return MDR_FAIL;

		timeout_ms -= elapsed_ms_since(&start);
		if (timeout_ms <= 0) {
			errno = ETIMEDOUT;
			return MDR_FAIL;
		}
		goto again;
	}

	if (c == 0)
		return 0;

	/*
	 * We have a full message, reset offset and do initial processing.
	 */
	mrh->offset = 0;

	if (umdr_init(&um, mrh->buf, c, MDR_FNONE) == MDR_FAIL) {
		snprintf(errmsg, sizeof(errmsg), "failed on umdr_init (%d)",
		    errno);
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_BEFAIL;
		pv[1].type = MDR_S;
		pv[1].v.s = errmsg;
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (writeall(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
	}

	if (!umdr_dcv_match(&um, MDR_DOMAIN_MDRD, MDR_MASK_D)) {
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_NOTSUPP;
		pv[1].type = MDR_S;
		pv[1].v.s = "message is not MDR_DOMAIN_MDRD";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (writeall(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_MDRD_BECLOSE:
		r = mdrd_unpack_beclose(&um, &id);
		break;
	case MDR_DCV_MDRD_BESESSERR:
		r = mdrd_unpack_besesserr(&um, &id);
		break;
	case MDR_DCV_MDRD_BEIN:
		r = umdr_unpack(&um, mdr_msg_mdrd_bein,
		    mrh->uv, UMDRVECLEN(mrh->uv));
		break;
	default:
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_NOTSUPP;
		pv[1].type = MDR_S;
		pv[1].v.s = "expected MDR_DCV_MDRD_BEREQ";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (writeall(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	if (r == MDR_FAIL) {
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_BADMSG;
		pv[1].type = MDR_S;
		pv[1].v.s = "unsupported message, or bad format";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (writeall(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	id = mrh->uv[0].v.u64;

	needle.id = id;
	sess = SPLAY_FIND(session_tree, &sessions, &needle);

	if (umdr_dcv(&um) == MDR_DCV_MDRD_BECLOSE ||
	    umdr_dcv(&um) == MDR_DCV_MDRD_BESESSERR) {
		if (sess != NULL)
			session_free(sess);
		/*
		 * No response is expected on BECLOSE/BESESSERR.
		 */
		goto again;
	}

	fd = mrh->uv[1].v.i32;
	peer = mrh->uv[2].v.b.bytes;
	peer_sz = mrh->uv[2].v.b.sz;
	port = mrh->uv[3].v.u16;
	mrh->msg = &mrh->uv[4].v.m;
	crt_bytes = mrh->uv[5].v.b.bytes;
	crt_len = mrh->uv[5].v.b.sz;

	if (sess == NULL) {
		sess = malloc(sizeof(struct mdrd_besession));
		if (sess == NULL) {
			/*
			 * We only use the session for id/fd in beout,
			 * so just use static storage for that purpose.
			 */
			bzero(&tmpsess, sizeof(tmpsess));
			tmpsess.id = id;
			tmpsess.fd = fd;
			mdrd_beout_error(&tmpsess, MDRD_BEOUT_FNONE,
			    MDR_ERR_BEFAIL, "mdrd session creation failed");
			goto again;
		}
		sess->id = id;
		sess->fd = fd;
		sess->is_new = 1;
		sess->must_free = 0;

		if (peer_sz == 16) {
			sess->peer_len = sizeof(struct sockaddr_in6);
			sess->peer.sin6_family = AF_INET6;
			sess->peer.sin6_port = htons(port);
			memcpy(sess->peer.sin6_addr.s6_addr, peer,
			    sizeof(sess->peer.sin6_addr.s6_addr));
			/* We don't carry the following info */
			sess->peer.sin6_flowinfo = 0;
			sess->peer.sin6_scope_id = 0;
		} else if (peer_sz == 4) {
			sess->peer_len = sizeof(struct sockaddr_in);
			peer4 = (struct sockaddr_in *)&sess->peer;
			peer4->sin_family = AF_INET;
			peer4->sin_port = htons(port);
			memcpy(&peer4->sin_addr.s_addr, peer,
			    sizeof(peer4->sin_addr.s_addr));
		} else {
			bzero(&sess->peer, sizeof(sess->peer));
			sess->peer_len = 0;
		}

		if (crt_len == 0)
			sess->cert = NULL;
		else
			sess->cert = d2i_X509(NULL, &crt_bytes, crt_len);

		sess->data = NULL;
		sess->free_data = NULL;
		clock_gettime(CLOCK_MONOTONIC, &sess->last_seen);
		SPLAY_INSERT(session_tree, &sessions, sess);
	} else {
		sess->is_new = 0;
		clock_gettime(CLOCK_MONOTONIC, &sess->last_seen);
	}

	mrh->session = sess;
	return c;
}

void
mdrd_besession_set_data(struct mdrd_besession *s, void *data,
    void(*free_data)(void *))
{
	s->data = data;
	s->free_data = free_data;
}
