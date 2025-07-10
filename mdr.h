#ifndef MDR_H
#define MDR_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "mdr_macros.h"

struct mdr_spec {
	uint64_t dcv;  /* domain/code/variant */
	uint8_t  types[];
};

enum mdr_type {
	MDR_U8,
	MDR_U16,
	MDR_U32,
	MDR_U64,

	MDR_I8,
	MDR_I16,
	MDR_I32,
	MDR_I64,

	MDR_F32,
	MDR_F64,

	MDR_S,
	MDR_B,
	MDR_M,
	MDR_R,

	MDR_AU8,
	MDR_AU16,
	MDR_AU32,
	MDR_AU64,

	MDR_AI8,
	MDR_AI16,
	MDR_AI32,
	MDR_AI64,

	MDR_AF32,
	MDR_AF64,

	MDR_AS,
	MDR_AB,
	MDR_AM
};

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
	uint64_t *dcv;  /* domain/code/variant */
	uint64_t *tail_bytes;

	/*
	 * Internal only; not part of wire payload.
	 */
	char     *buf;
	size_t    buf_sz;
	char     *pos;
	int       dyn;
};

struct mdr_bytes_in {
	const char *data;
	uint64_t    length;
};

struct mdr_bytes_out {
	const char **data;
	uint64_t    *length;
};

struct mdr_in {
	uint8_t type;
	union {
		uint8_t  u8;
		struct {
			uint32_t  length;
			uint8_t  *items;
		} Au8;

		uint16_t u16;
		struct {
			uint32_t  length;
			uint16_t *items;
		} Au16;

		uint32_t u32;
		struct {
			uint32_t  length;
			uint32_t *items;
		} Au32;

		uint64_t u64;
		struct {
			uint32_t  length;
			uint64_t *items;
		} Au64;

		int8_t   i8;
		struct {
			uint32_t  length;
			int8_t   *items;
		} Ai8;

		int16_t  i16;
		struct {
			uint32_t  length;
			int16_t  *items;
		} Ai16;

		int32_t  i32;
		struct {
			uint32_t  length;
			int32_t  *items;
		} Ai32;

		int64_t  i64;
		struct {
			uint32_t  length;
			int64_t  *items;
		} Ai64;

		float    f32;
		struct {
			uint32_t  length;
			float    *items;
		} Af32;

		double   f64;
		struct {
			uint32_t  length;
			double   *items;
		} Af64;

		const struct mdr *m;
		struct {
			uint32_t    length;
			struct mdr *items;
		} Am;

		struct mdr_bytes_in s, b;
		struct {
			uint32_t             length;
			struct mdr_bytes_in *items;
		} As, Ab;

		struct space {
			char     **dst;
			uint64_t   length;
		} space;
	} v;
};

struct mdr_out {
	uint8_t type;
	union {
		uint8_t  *u8;
		struct {
			uint32_t  *length;
			uint8_t  **items;
		} Au8;

		uint16_t *u16;
		struct {
			uint32_t  *length;
			uint16_t **items;
		} Au16;

		uint32_t *u32;
		struct {
			uint32_t  *length;
			uint32_t **items;
		} Au32;

		uint64_t *u64;
		struct {
			uint32_t  *length;
			uint64_t **items;
		} Au64;

		int8_t   *i8;
		struct {
			uint32_t  *length;
			int8_t   **items;
		} Ai8;

		int16_t  *i16;
		struct {
			uint32_t  *length;
			int16_t  **items;
		} Ai16;

		int32_t  *i32;
		struct {
			uint32_t  *length;
			int32_t  **items;
		} Ai32;

		int64_t  *i64;
		struct {
			uint32_t  *length;
			int64_t  **items;
		} Ai64;

		float    *f32;
		struct {
			uint32_t  *length;
			float    **items;
		} Af32;

		double   *f64;
		struct {
			uint32_t  *length;
			double   **items;
		} Af64;

		struct {
			struct mdr *m;
			char       *buf;
			uint64_t    buf_sz;
		} m;
		struct {
			uint32_t    *length;
			struct mdr **items;
		} Am;

		struct mdr_bytes_out s, b;
		struct {
			uint64_t             *length;
			struct mdr_bytes_out *items;
		} As, Ab;
	} v;
};

#define MDR_FAIL -1
#define MDR_DCV(domain, code, variant) \
    ((uint64_t)domain << 32 | (uint64_t)code << 16 | (uint64_t)variant)

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

uint64_t mdr_mkdcv(uint32_t, uint16_t, uint16_t);

uint32_t mdr_flags(const struct mdr *);
uint32_t mdr_domain(const struct mdr *);
uint16_t mdr_code(const struct mdr *);
uint16_t mdr_variant(const struct mdr *);
uint64_t mdr_dcv(const struct mdr *);
uint64_t mdr_tail_bytes(const struct mdr *);

ptrdiff_t mdr_pack_(int, struct mdr *, char *, size_t, uint32_t,
              uint64_t, const char *, ...);
ptrdiff_t mdr_pack_hdr(struct mdr *, char *, size_t, uint32_t, uint64_t);
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

#define MDR_NS_MDRD               0x00000001
#define MDR_NAME_MDRD_ERROR       0x0001
#define MDR_NAME_MDRD_BEREQ       0x0002
#define MDR_NAME_MDRD_BERESP      0x0003
#define MDR_NAME_MDRD_BERESP_WMSG     0x0001
#define MDR_NAME_MDRD_BECLOSE     0x0004

#endif
