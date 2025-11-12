#include <errno.h>
#include <stdlib.h>
#include "mdr.h"
#include "mdrd.h"

int
mdrd_unpack_beclose(struct mdr *m, uint64_t *id)
{
	struct mdr_out m_out[1];

	if (mdr_unpack_payload(m, mdr_msg_mdrd_beclose, m_out, 1) == MDR_FAIL)
		return MDR_FAIL;
	*id = m_out[0].v.u64;

	return 0;
}

int
mdrd_unpack_bereq(struct mdr *m, uint64_t *id, int *fd, struct sockaddr *peer,
    socklen_t *slen, struct mdr *msg, X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;
	const uint8_t       *peer_addr;
	size_t               peer_addr_sz;
	uint16_t             port;
	struct sockaddr_in6 *peer6;
	struct sockaddr_in  *peer4;
	struct mdr_out       m_out[6];

	if (id == NULL || fd == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (mdr_unpack_payload(m, mdr_msg_mdrd_bereq, m_out, 6) == MDR_FAIL)
		return MDR_FAIL;

	*id = m_out[0].v.u64;
	*fd = m_out[1].v.i32;
	peer_addr = m_out[2].v.b.bytes;
	peer_addr_sz = m_out[2].v.b.sz;
	port = m_out[3].v.u16;
	mdr_copy(msg, &m_out[4].v.m);
	p = m_out[5].v.b.bytes;
	cert_len = m_out[5].v.b.sz;

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
mdrd_unpack_error(struct mdr *m, uint32_t *status, const char **reason,
    uint64_t *reason_sz)
{
	struct mdr_out m_out[2];

	if (mdr_unpack_payload(m, mdr_msg_mdrd_error, m_out, 1) == MDR_FAIL)
		return MDR_FAIL;
	*status = m_out[0].v.u32;
	*reason = m_out[1].v.s.bytes;
	*reason_sz = m_out[1].v.s.sz;

	return 0;
}
