/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <mdr/mdr.h>

/* Backend response flags */
#define MDRD_BEOUT_FNONE  0x00000000
#define MDRD_BEOUT_FCLOSE 0x00000001  /* Client connection should be closed */

__BEGIN_DECLS

struct mdrd_recvhdl
{
	/*
	 * User-provided fields
	 */
	void                  *buf;
	size_t                 bufsz;

	/*
	 * We need the umdr_vec here so the message doesn't
	 * go out of scope.
	 */
	struct umdr_vec        uv[6];
	size_t                 offset;

	/* Read fields */
	const struct umdr     *msg;
	struct mdrd_besession *session;
};

struct mdrd_besession
{
	uint64_t                     id;
	int                          fd;
	int                          is_new;
	X509                        *cert;
	struct sockaddr_in6          peer;
	socklen_t                    peer_len;
	void                        *data;
	void                         (*free_data)(void *);
	struct timespec              last_seen;
	int                          must_free;
	SPLAY_ENTRY(mdrd_besession)  entries;
};

ptrdiff_t mdrd_recv(struct mdrd_recvhdl *, int);
void      mdrd_besession_set_data(struct mdrd_besession *, void *,
              void(*)(void *));
int       mdrd_purge_sessions(time_t);

int mdrd_unpack_beclose(struct umdr *, uint64_t *);
int mdrd_unpack_bein(struct umdr *, uint64_t *, int *, struct sockaddr *,
        socklen_t *, struct umdr *, X509 **);
int mdrd_unpack_besesserr(struct umdr *, uint64_t *);
int mdrd_beout_error(const struct mdrd_besession *, uint32_t, uint32_t,
        const char *);
int mdrd_beout_ok(const struct mdrd_besession *, uint32_t);
int mdrd_beout(const struct mdrd_besession *, uint32_t, const struct pmdr *);

__END_DECLS

#endif
