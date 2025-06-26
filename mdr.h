#ifndef MDR_H
#define MDR_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "mdr_macros.h"

/*
 * Minimal Data Representation
 *
 * An mdr message can contain at most PTRDIFF_MAX bytes.
 */
struct mdr {
	/*
	 * Big-endian over the wire. Minimum size is thus 20 bytes.
	 */
	uint64_t *size;

	/*
	 * Flags can be used to provide generic information to implementations
	 * that are otherwise unaware of the specific structure of the data.
	 */
	uint32_t *flags;
#define MDR_F_NONE       0x00000000
#define MDR_F_TAIL_BYTES 0x00000001
	/* Other flags reserved for future use */

	/*
	 * Namespace, name and variant is used to identify
	 * the data structure globally across many services.
	 *
	 * For instance, namespace may be used as a service identifier,
	 * while name can identify the type of request and variant can
	 * allow defining multiple revisions or variantions of this requests,
	 * like adding new fields, optional fields, etc.
	 */
	// TODO: pack namespace/name/variant in a single uint64_t
	// ... or domain/code/variant. Use a function to simplify packing
	// it. This will make it easy to do a switch statement for any
	// combination.
	uint32_t *namespace;
	uint16_t *name;
	uint16_t *variant;
	uint64_t *tail_bytes;

	/*
	 * Internal only; not part of wire payload.
	 */
	char     *buf;
	size_t    buf_sz;
	char     *pos;
	int       dyn;
};

#define MDR_FAIL -1

const void *mdr_buf(const struct mdr *);
void        mdr_free(struct mdr *);
uint64_t    mdr_size(const struct mdr *);
size_t      mdr_hdr_size(uint32_t);
int         mdr_rewind(struct mdr *);
ptrdiff_t   mdr_tell(const struct mdr *);
// TODO: change seek so it takes a format and thus jump the right number
// of bytes for sN, bN, rN, m, A*. Maybe use unpackf with NULL args.
ptrdiff_t   mdr_seek(struct mdr *, ptrdiff_t);
uint64_t    mdr_pending(const struct mdr *);
ptrdiff_t   mdr_copy(struct mdr *, char *, size_t, const struct mdr *);

uint32_t mdr_flags(const struct mdr *);
uint32_t mdr_namespace(const struct mdr *);
uint16_t mdr_name(const struct mdr *);
uint16_t mdr_variant(const struct mdr *);
uint64_t mdr_tail_bytes(const struct mdr *);

ptrdiff_t mdr_pack_(int, struct mdr *, char *, size_t, uint32_t,
              uint16_t, uint16_t, uint16_t, const char *, ...);
ptrdiff_t mdr_pack_hdr(struct mdr *, char *, size_t, uint32_t, uint16_t,
              uint16_t, uint16_t);
ptrdiff_t mdr_pack_int8(struct mdr *, int8_t);
ptrdiff_t mdr_pack_int16(struct mdr *, int16_t);
ptrdiff_t mdr_pack_int32(struct mdr *, int32_t);
ptrdiff_t mdr_pack_int64(struct mdr *, int64_t);
ptrdiff_t mdr_pack_uint8(struct mdr *, uint8_t);
ptrdiff_t mdr_pack_uint16(struct mdr *, uint16_t);
ptrdiff_t mdr_pack_uint32(struct mdr *, uint32_t);
ptrdiff_t mdr_pack_uint64(struct mdr *, uint64_t);
ptrdiff_t mdr_pack_float32(struct mdr *, float);
ptrdiff_t mdr_pack_float64(struct mdr *, double);
ptrdiff_t mdr_pack_bytes(struct mdr *, const char *, uint64_t);
ptrdiff_t mdr_pack_space(struct mdr *, char **, uint64_t);
ptrdiff_t mdr_pack_string(struct mdr *, const char *, int64_t);
ptrdiff_t mdr_pack_mdr(struct mdr *, struct mdr *);
ptrdiff_t mdr_pack_array_of(struct mdr *, const char *, int32_t, void *,
              uint64_t);
ptrdiff_t mdr_packf_(int, struct mdr *, const char *, ...);
ptrdiff_t mdr_add_tail_bytes(struct mdr *, uint64_t);

ptrdiff_t mdr_unpack_(int, struct mdr *, uint32_t, char *, size_t,
              const char *, ...);
ptrdiff_t mdr_unpack_from_fd(struct mdr *, uint32_t, int, char *, size_t);
ptrdiff_t mdr_unpack_all(struct mdr *, uint32_t, char *, size_t, size_t);
ptrdiff_t mdr_unpack_hdr(struct mdr *, uint32_t, char *, size_t);
ptrdiff_t mdr_unpack_int8(struct mdr *, int8_t *);
ptrdiff_t mdr_unpack_int16(struct mdr *, int16_t *);
ptrdiff_t mdr_unpack_int32(struct mdr *, int32_t *);
ptrdiff_t mdr_unpack_int64(struct mdr *, int64_t *);
ptrdiff_t mdr_unpack_uint8(struct mdr *, uint8_t *);
ptrdiff_t mdr_unpack_uint16(struct mdr *, uint16_t *);
ptrdiff_t mdr_unpack_uint32(struct mdr *, uint32_t *);
ptrdiff_t mdr_unpack_uint64(struct mdr *, uint64_t *);
ptrdiff_t mdr_unpack_float32(struct mdr *, float *);
ptrdiff_t mdr_unpack_float64(struct mdr *, double *);
ptrdiff_t mdr_unpack_bytes(struct mdr *, char *, uint64_t *);
ptrdiff_t mdr_unpack_bytes_ref(struct mdr *, const char **, uint64_t *);
ptrdiff_t mdr_unpack_string(struct mdr *, char *, uint64_t *);
ptrdiff_t mdr_unpack_mdr_ref(struct mdr *, struct mdr *);
ptrdiff_t mdr_unpack_mdr(struct mdr *, struct mdr *, char *, size_t);
ptrdiff_t mdr_unpack_array_of(struct mdr *, const char *, int32_t *,
              void *, uint64_t *);
ptrdiff_t mdr_unpackf_(int, struct mdr *, const char *, ...);
void      mdr_print(FILE *, const struct mdr *);

ptrdiff_t mdr_pack_echo(struct mdr *, const char *);
ptrdiff_t mdr_unpack_echo(struct mdr *, char *, size_t, char *, size_t *);

/*
 * Namespaces are 32 bits. The most significant bit is reserved for
 * future use, which in effect means the highest namespace is 0x7FFFFFFF.
 * IDs are 16 bits.
 */

#define MDR_NS_RESERVED      0x80000000

#define MDR_NS_MDR           0x00000000
#define MDR_NAME_MDR_PING        0x0001
#define MDR_NAME_MDR_PONG        0x0002
#define MDR_NAME_MDR_TEST        0x0003
#define MDR_NAME_MDR_ECHO        0x0004

#define MDR_NS_MDRD          0x00000001
#define MDR_NAME_MDRD_ERROR      0x0001
#define MDR_NAME_MDRD_BEREQ      0x0002
#define MDR_NAME_MDRD_BERESP     0x0003
#define MDR_NAME_MDRD_BECLOSE    0x0004

#endif
