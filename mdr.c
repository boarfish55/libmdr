#include <sys/param.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mdr.h"

static ssize_t
readall(int fd, void *buf, size_t count)
{
        ssize_t r;
        ssize_t n = 0;

        while (n < count) {
                r = read(fd, buf + n, count - n);
                if (r == -1) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                } else if (r == 0) {
                        return n;
                }
                n += r;
        }
        return n;
}

static int
mdr_can_fit(struct mdr *m, size_t n)
{
	char *tmp;

	if ((PTRDIFF_MAX - mdr_tell(m)) < n) {
		errno = EOVERFLOW;
		return 0;
	}

	if (m->buf_sz >= mdr_tell(m) + n)
		return 1;

	if (!m->dyn) {
		errno = EOVERFLOW;
		return 0;
	}

	if ((tmp = realloc(m->buf, mdr_tell(m) + n)) == NULL)
		return 0;

	m->buf_sz = mdr_tell(m) + n;
	if (tmp != m->buf) {
		m->pos = tmp + mdr_tell(m);

		m->size = (uint64_t *)(tmp + ((char *)m->size - m->buf));
		m->flags = (uint32_t *)(tmp + ((char *)m->flags - m->buf));
		m->dcv = (uint64_t *)(tmp + ((char *)m->dcv - m->buf));

		if (mdr_flags(m) & MDR_F_TAIL_BYTES)
			m->tail_bytes = (uint64_t *)
			    (tmp + ((char *)m->tail_bytes - m->buf));

		m->buf = tmp;
	}

	return 1;
}

static ptrdiff_t
mdr_vpackf(int argc, int validate_argc_only, struct mdr *m, const char *spec,
    va_list ap)
{
	int          finish = 0;
	const char  *p, *prev;
	void        *array;
	const char  *bytes;
	char       **bytes_p;
	char        *end;
	uint64_t     bytes_sz;
	int64_t      slen;
	uint64_t     max_item_sz;
	uint64_t     bits;
	int32_t      n;
	/*
	 * A specifier can be at most 5 bytes: "A" for array, then 3
	 * chars, for example u64, and terminating NUL.
	 */
	char        spbuf[5];

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/* We only handle up to 256 variadic fields. */
	if (argc > MDR_STDARG_MAX)
		abort();

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   f32, f64,
	 *   bN, sN, m, rN ("r" for "reserve")
	 * An "A" prefix can be used to specify an array.
	 */
	for (p = spec, prev = spec; !finish; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (p - prev > sizeof(spbuf) - 1) {
			errno = EINVAL;
			return MDR_FAIL;
		}

		memcpy(spbuf, prev, p - prev);
		spbuf[p - prev] = '\0';
		argc--;

		if (spbuf[0] == 'A') {
			argc--;
			if (spbuf[1] == 'b' || spbuf[1] == 'r' ||
			    spbuf[1] == 's')
				argc--;
		}

		if (spbuf[0] == 'b' || spbuf[0] == 'r' || spbuf[0] == 's')
			argc--;

		/* We have more format specifiers than we have args. */
		if (argc < 0)
			abort();

		if (spbuf[0] == 'A') {
			n = va_arg(ap, int32_t);
			array = va_arg(ap, void *);
			if (spbuf[1] == 'b' || spbuf[1] == 'r' ||
			    spbuf[1] == 's')
				max_item_sz = va_arg(ap, uint64_t);
			if (!validate_argc_only &&
			    mdr_pack_array_of(m, spbuf + 1, n, array,
			    max_item_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "m") == 0) {
			if (!validate_argc_only &&
			    mdr_pack_mdr(m, va_arg(ap, struct mdr *))
			    == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "bN") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t);
			if (!validate_argc_only &&
			    mdr_pack_bytes(m, bytes, bytes_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "rN") == 0) {
			bytes_p = va_arg(ap, char **);
			bytes_sz = va_arg(ap, uint64_t);
			if (!validate_argc_only &&
			    mdr_pack_space(m, bytes_p, bytes_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "sN") == 0) {
			bytes = va_arg(ap, char *);
			slen = va_arg(ap, int64_t);
			if (!validate_argc_only &&
			    mdr_pack_string(m, bytes, slen) == MDR_FAIL)
				return MDR_FAIL;
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (bits == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 8:
				if (!validate_argc_only &&
				    mdr_pack_uint8(m, va_arg(ap, int))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 16:
				if (!validate_argc_only &&
				    mdr_pack_uint16(m, va_arg(ap, int))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 32:
				if (!validate_argc_only &&
				    mdr_pack_uint32(m, va_arg(ap, uint32_t))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 64:
				if (!validate_argc_only &&
				    mdr_pack_uint64(m, va_arg(ap, uint64_t))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else if (spbuf[0] == 'f') {
			if (strlen(spbuf) < 3) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (bits == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 32:
				if (!validate_argc_only &&
				    mdr_pack_float32(m, va_arg(ap, double))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 64:
				if (!validate_argc_only &&
				    mdr_pack_float64(m, va_arg(ap, double))
				    == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else {
			/* Unknown type specifier */
			errno = EINVAL;
			return MDR_FAIL;
		}
		prev = p + 1;
	}

	/* We have more args than format specifiers. */
	if (argc > 0)
		abort();

	return mdr_tell(m);
}

static ptrdiff_t
mdr_vunpackf(int argc, int validate_argc_only, struct mdr *m, const char *spec,
    va_list ap)
{
	int          finish = 0;
	const char  *p, *prev;
	char        *bytes, *end;
	void        *array;
	const char **bytes_ref;
	uint64_t    *bytes_sz;
	uint64_t    *max_item_sz;
	uint64_t     bits;
	int32_t     *n;
	/*
	 * A specifier can be at most 5 bytes: "A" for array, then 3
	 * chars, for example u64, and terminating NUL.
	 */
	char        spbuf[5];

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/* We only handle up to 256 variadic fields. */
	if (argc > MDR_STDARG_MAX)
		abort();

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   f32, f64,
	 *   bN, sN, m, rN (reference to bytes)
	 * An "A" prefix can be used to specify an array.
	 */
	for (p = spec, prev = spec; !finish; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (p - prev > sizeof(spbuf) - 1) {
			errno = EINVAL;
			return MDR_FAIL;
		}

		memcpy(spbuf, prev, p - prev);
		spbuf[p - prev] = '\0';
		argc--;

		if (spbuf[0] == 'A') {
			argc--;
			if (spbuf[1] == 'b' || spbuf[1] == 'r' ||
			    spbuf[1] == 's')
				argc--;
		}

		if (spbuf[0] == 'b' || spbuf[0] == 'r' || spbuf[0] == 's')
			argc--;

		/* We have more format specifiers than we have args. */
		if (argc < 0)
			abort();

		if (spbuf[0] == 'A') {
			n = va_arg(ap, int32_t *);
			array = va_arg(ap, void *);
			if (spbuf[1] == 'b' || spbuf[1] == 'r' ||
			    spbuf[1] == 's')
				max_item_sz = va_arg(ap, uint64_t *);
			else
				max_item_sz = NULL;
			if (!validate_argc_only &&
			    mdr_unpack_array_of(m, spbuf + 1, n,
			    array, max_item_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "m") == 0) {
			if (!validate_argc_only &&
			    mdr_unpack_mdr_ref(m, va_arg(ap, struct mdr *))
			    == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "bN") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t *);
			if (!validate_argc_only &&
			    mdr_unpack_bytes(m, bytes, bytes_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "rN") == 0) {
			bytes_ref = va_arg(ap, const char **);
			bytes_sz = va_arg(ap, uint64_t *);
			if (!validate_argc_only &&
			    mdr_unpack_bytes_ref(m, bytes_ref, bytes_sz)
			    == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "sN") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t *);
			if (!validate_argc_only &&
			    mdr_unpack_string(m, bytes, bytes_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (bits == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 8:
				if (!validate_argc_only &&
				    mdr_unpack_uint8(m,
				    va_arg(ap, uint8_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 16:
				if (!validate_argc_only &&
				    mdr_unpack_uint16(m,
				    va_arg(ap, uint16_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 32:
				if (!validate_argc_only &&
				    mdr_unpack_uint32(m,
				    va_arg(ap, uint32_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (!validate_argc_only &&
				    mdr_unpack_uint64(m,
				    va_arg(ap, uint64_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else if (spbuf[0] == 'f') {
			if (strlen(spbuf) < 3) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (bits == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 32:
				if (!validate_argc_only &&
				    mdr_unpack_float32(m,
				    va_arg(ap, float *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (!validate_argc_only &&
				    mdr_unpack_float64(m,
				    va_arg(ap, double *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else {
			/* Unknown type specifier */
			errno = EINVAL;
			return MDR_FAIL;
		}
		prev = p + 1;
	}

	/* We have more args than format specifiers. */
	if (argc > 0)
		abort();

	return mdr_tell(m);
}

uint64_t
mdr_mkdcv(uint32_t domain, uint16_t code, uint16_t variant)
{
	uint64_t dcv = 0;
	dcv |= (uint64_t)domain << 32;
	dcv |= (uint64_t)code << 16;
	dcv |= (uint64_t)variant;
	return dcv;
}

uint64_t
mdr_dcv(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return be64toh(*m->dcv);
}

ptrdiff_t
mdr_copy(struct mdr *dst, char *buf, size_t buf_sz, const struct mdr *src)
{
	ptrdiff_t r;

	if ((r = mdr_pack_hdr(dst, buf, buf_sz, mdr_flags(src),
	    mdr_dcv(src))) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(src) > buf_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	memcpy(dst->pos, mdr_buf(src) + mdr_hdr_size(mdr_flags(src)),
	    mdr_size(src) - mdr_hdr_size(mdr_flags(src)));

	*dst->size = htobe64(mdr_size(dst) +
	    (mdr_size(src) - mdr_hdr_size(mdr_flags(src))));

	return 0;
}

static ptrdiff_t
mdr_update_size(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	*m->size = htobe64(mdr_tell(m));

	/*
	 * We return the size without trailing bytes to make
	 * it easy for callers to know where to start appending bytes
	 * in a buffer.
	 */
	return mdr_tell(m);
}

void
mdr_free(struct mdr *m)
{
	if (m == NULL)
		return;
	if (m->dyn)
		free(m->buf);
	bzero(m, sizeof(struct mdr));
}

size_t
mdr_hdr_size(uint32_t flags)
{
	size_t n;
	/*
	 * Header format is as follows, all integers in big-endian:
	 *  - size:       uint64_t
	 *  - flags:      uint32_t
	 *  - namespace:  uint32_t
	 *  - name:       uint16_t
	 *  - variant:    uint16_t
	 *  - tail_bytes: uint64_t (optional)
	 */
	n = sizeof(uint64_t) +
	    (2 * sizeof(uint32_t)) +
	    (2 * sizeof(uint16_t));
	if (flags & MDR_F_TAIL_BYTES)
		n += sizeof(uint64_t);
	return n;
}

uint64_t
mdr_size(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	return be64toh(*m->size);
}

ptrdiff_t
mdr_tell(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	return m->pos - m->buf;
}

ptrdiff_t
mdr_seek(struct mdr *m, ptrdiff_t offset)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	m->pos = MIN(m->buf + offset, m->buf + m->buf_sz);
	return m->pos - m->buf;
}

uint64_t
mdr_pending(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	if (m->buf_sz >= mdr_size(m))
		return 0;
	return mdr_size(m) - m->buf_sz;
}

int
mdr_rewind(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	m->pos = m->buf + mdr_hdr_size(mdr_flags(m));
	return 0;
}

uint32_t
mdr_flags(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return be32toh(*m->flags);
}

uint32_t
mdr_domain(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return (uint32_t)(be64toh(*m->dcv) >> 32);
}

uint16_t
mdr_code(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (uint16_t)((be64toh(*m->dcv) & 0x00000000ffff0000) >> 16);
}

uint16_t
mdr_variant(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (uint16_t)(be64toh(*m->dcv) & 0x000000000000ffff);
}

uint64_t
mdr_tail_bytes(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	if (!(mdr_flags(m) & MDR_F_TAIL_BYTES))
		return 0;
	return be64toh(*m->tail_bytes);
}

const void *
mdr_buf(const struct mdr *m)
{
	return m->buf;
}

ptrdiff_t
mdr_pack_(int argc, struct mdr *m, char *buf, size_t buf_sz, uint32_t flags,
    uint64_t dcv, const char *spec, ...)
{
	ptrdiff_t r;
	va_list   ap;

	if (mdr_pack_hdr(m, buf, buf_sz, flags, dcv) == MDR_FAIL)
		return MDR_FAIL;

	va_start(ap, spec);
	r = mdr_vpackf(argc, 1, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	va_start(ap, spec);
	r = mdr_vpackf(argc, 0, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	return mdr_tell(m);
}

ptrdiff_t
mdr_pack_hdr(struct mdr *m, char *buf, size_t buf_sz, uint32_t flags,
    uint64_t dcv)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf != NULL) {
		if (buf_sz < mdr_hdr_size(flags)) {
			errno = EOVERFLOW;
			return MDR_FAIL;
		}
		m->buf = buf;
		m->buf_sz = buf_sz;
		m->dyn = 0;
	} else {
		if ((m->buf = malloc(mdr_hdr_size(flags) + buf_sz)) == NULL)
			return MDR_FAIL;
		m->buf_sz = mdr_hdr_size(flags) + buf_sz;
		m->dyn = 1;
	}

	m->pos = m->buf;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (flags & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
		*m->tail_bytes = 0;

	} else {
		m->tail_bytes = NULL;
	}

	*m->flags = htobe32(flags);
	*m->dcv = htobe64(dcv);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_int64(struct mdr *m, int64_t v)
{
	return mdr_pack_uint64(m, (uint64_t)v);
}

ptrdiff_t
mdr_pack_int32(struct mdr *m, int32_t v)
{
	return mdr_pack_uint32(m, (uint32_t)v);
}

ptrdiff_t
mdr_pack_int16(struct mdr *m, int16_t v)
{
	return mdr_pack_uint16(m, (uint16_t)v);
}

ptrdiff_t
mdr_pack_int8(struct mdr *m, int8_t v)
{
	return mdr_pack_uint8(m, (uint8_t)v);
}

ptrdiff_t
mdr_pack_uint64(struct mdr *m, uint64_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint64_t)))
		return MDR_FAIL;

	*(uint64_t *)m->pos = htobe64(v);
	m->pos += sizeof(uint64_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint32(struct mdr *m, uint32_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint32_t)))
		return MDR_FAIL;

	*(uint32_t *)m->pos = htobe32(v);
	m->pos += sizeof(uint32_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint16(struct mdr *m, uint16_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint16_t)))
		return MDR_FAIL;

	*(uint16_t *)m->pos = htobe16(v);
	m->pos += sizeof(uint16_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint8(struct mdr *m, uint8_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint8_t)))
		return MDR_FAIL;

	*(uint8_t *)m->pos = v;
	m->pos += sizeof(uint8_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_float32(struct mdr *m, float v)
{
	union {
		float    f;
		uint32_t i;
	} f = { v };

	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(float)))
		return MDR_FAIL;

	*(uint32_t *)m->pos = htobe32(f.i);
	m->pos += sizeof(uint32_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_float64(struct mdr *m, double v)
{
	union {
		double   f;
		uint64_t i;
	} f = { v };

	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(double)))
		return MDR_FAIL;

	*(uint64_t *)m->pos = htobe64(f.i);
	m->pos += sizeof(uint64_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_bytes(struct mdr *m, const char *bytes, uint64_t bytes_sz)
{
	if (m == NULL || bytes_sz & 0x8000000000000000) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, bytes_sz +
	    ((bytes_sz <= 0x7f) ? sizeof(uint8_t) : sizeof(uint64_t))))
		return MDR_FAIL;

	/*
	 * Only store the byte string length as a single byte if the leading
	 * bit is zero. Otherwise use the full 8 bytes. This should prevent
	 * wasting 7 bytes for large numbers of small strings.
	 */
	if (bytes_sz <= 0x7f) {
		*(uint8_t *)m->pos = (uint8_t)bytes_sz;
		m->pos += sizeof(uint8_t);
	} else {
		*(uint64_t *)m->pos = htobe64(bytes_sz | 0x8000000000000000);
		m->pos += sizeof(uint64_t);
	}

	memcpy(m->pos, bytes, bytes_sz);
	m->pos += bytes_sz;

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_space(struct mdr *m, char **dst, uint64_t bytes_sz)
{
	if (m == NULL || bytes_sz & 0x8000000000000000) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, bytes_sz +
	    ((bytes_sz <= 0x7f) ? sizeof(uint8_t) : sizeof(uint64_t))))
		return MDR_FAIL;

	/*
	 * Only store the byte string length as a single byte if the leading
	 * bit is zero. Otherwise use the full 8 bytes. This should prevent
	 * wasting 7 bytes for large numbers of small strings.
	 */
	if (bytes_sz <= 0x7f) {
		*(uint8_t *)m->pos = (uint8_t)bytes_sz;
		m->pos += sizeof(uint8_t);
	} else {
		*(uint64_t *)m->pos = htobe64(bytes_sz | 0x8000000000000000);
		m->pos += sizeof(uint64_t);
	}

	*dst = m->pos;
	m->pos += bytes_sz;

	return mdr_update_size(m);
}

ptrdiff_t
mdr_add_tail_bytes(struct mdr *m, uint64_t bytes_sz)
{
	if (m == NULL || !(mdr_flags(m) & MDR_F_TAIL_BYTES)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (UINT64_MAX - mdr_tail_bytes(m) < bytes_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	*m->tail_bytes = htobe64(mdr_tail_bytes(m) + bytes_sz);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_string(struct mdr *m, const char *bytes, int64_t maxlen)
{
	size_t len = strlen(bytes);
	if (maxlen < 0)
		maxlen = INT64_MAX;
	return mdr_pack_bytes(m, bytes, MIN(len, maxlen));
}

ptrdiff_t
mdr_pack_mdr(struct mdr *m, struct mdr *src)
{
	if (m == NULL || src == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, mdr_size(src)))
		return MDR_FAIL;

	memcpy(m->pos, mdr_buf(src), mdr_size(src));
	m->pos += mdr_size(src);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_array_of(struct mdr *m, const char *type, int32_t n,
    void *a, uint64_t bytes_sz)
{
	int       i;
	uint64_t  bits;
	char     *end;

	if (n > 0x7fffffff) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (*type == 's' || *type == 'b' || *type == 'm') {
		if (n < 0)
			n = 0x7fffffff;
		for (i = 0; i < n; i++) {
			if (((void **)a)[i] == NULL) {
				n = i;
				break;
			}
		}
	}

	if (n <= 0x7f) {
		*(uint8_t *)m->pos = n;
		m->pos += sizeof(uint8_t);
	} else {
		*(uint32_t *)m->pos = htobe32(n | 0x80000000);
		m->pos += sizeof(uint32_t);
	}

	if (*type == 'i' || *type == 'u' || *type == 'f') {
		bits = strtoull(type + 1, &end, 10);
		if (bits == ULLONG_MAX || *end != '\0') {
			errno = EINVAL;
			return MDR_FAIL;
		}
	}

	for (i = 0; i < n; i++) {
		switch (*type) {
		case 'i':
		case 'u':
			switch (bits) {
			case 8:
				if (mdr_pack_uint8(m, ((uint8_t *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 16:
				if (mdr_pack_uint16(m, ((uint16_t *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 32:
				if (mdr_pack_uint32(m, ((uint32_t *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (mdr_pack_uint64(m, ((uint64_t *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
			break;
		case 'f':
			switch (bits) {
			case 32:
				if (mdr_pack_float32(m, ((float *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (mdr_pack_float64(m, ((double *)a)[i])
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
			break;
		case 'b':
			if (mdr_pack_bytes(m, ((char **)a)[i], bytes_sz)
			    == MDR_FAIL)
				return MDR_FAIL;
			break;
		case 's':
			if (mdr_pack_string(m, ((char **)a)[i], bytes_sz)
			    == MDR_FAIL)
				return MDR_FAIL;
			break;
		case 'm':
			if (mdr_pack_mdr(m, (struct mdr *)a + i)
			    == MDR_FAIL)
				return MDR_FAIL;
		}
	}

	return mdr_tell(m);
}

ptrdiff_t
mdr_packf_(int argc, struct mdr *m, const char *spec, ...)
{
	va_list     ap;
	ptrdiff_t   r;

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	va_start(ap, spec);
	r = mdr_vpackf(argc, 1, m, spec, ap);
	va_end(ap);

	va_start(ap, spec);
	r = mdr_vpackf(argc, 0, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	return mdr_tell(m);
}

/*
 * fd must be blocking.
 */
ptrdiff_t
mdr_unpack_from_fd(struct mdr *m, uint32_t allowed_flags, int fd,
    char *buf, size_t buf_sz)
{
	int r;

	if (m == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	r = readall(fd, buf, mdr_hdr_size(0));
	if (r == -1)
		return -1;
	else if (r == 0)
		return 0;

	if (mdr_unpack_hdr(m, allowed_flags, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(m) > buf_sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	r = readall(fd, buf + r, mdr_size(m) - r);
	if (r == -1) {
		return -1;
	} else if (r == 0) {
		errno = EPIPE;
		return -1;
	}

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_all(struct mdr *m, uint32_t allowed_flags, char *buf,
    size_t buf_sz, size_t max_sz)
{
	if (mdr_unpack_hdr(m, allowed_flags, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	if (max_sz > 0 && mdr_size(m) > max_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	if (mdr_pending(m) > 0) {
		errno = EAGAIN;
		return MDR_FAIL;
	}
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_hdr(struct mdr *m, uint32_t allowed_flags, char *buf, size_t buf_sz)
{
	if (m == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->buf = buf;
	m->buf_sz = buf_sz;
	m->pos = m->buf;
	m->tail_bytes = 0;
	m->dyn = 0;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	if (mdr_size(m) == UINT64_MAX) {
		errno = ERANGE;
		return MDR_FAIL;
	}

	/*
	 * Make sure we never try to unpack bytes past
	 * the end of our message.
	 */
	if (m->buf_sz > mdr_size(m))
		m->buf_sz = mdr_size(m);

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	/*
	 * Some flags (MDR_F_TAIL_BYTES) could have
	 * security implications and therefore refuse
	 * to unpack an mdr unless we explicitly allow
	 * specified flags.
	 */
	if ((mdr_flags(m) & ~allowed_flags) != 0) {
		errno = EACCES;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(mdr_flags(m))) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (mdr_flags(m) & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
	} else {
		m->tail_bytes = NULL;
	}

	return mdr_tell(m);
}

void
mdr_print(FILE *out, const struct mdr *m)
{
	const char *b;
	int         i;

	if (m == NULL)
		return;

	fprintf(out, "  size:        %lu\n", mdr_size(m));
	fprintf(out, "  domain:      %u\n", mdr_domain(m));
	fprintf(out, "  code:        %u\n", mdr_code(m));
	fprintf(out, "  variant:     %u\n", mdr_variant(m));
	if (mdr_flags(m) & MDR_F_TAIL_BYTES)
		fprintf(out, "  tail bytes:  %lu\n", mdr_tail_bytes(m));
	fprintf(out, "\n");
	fprintf(out, "  payload (%lu bytes):\n",
	    mdr_size(m) - mdr_hdr_size(mdr_flags(m)));

	for (b = mdr_buf(m) + mdr_hdr_size(mdr_flags(m)), i = 0;
	    b - (char *)mdr_buf(m) < mdr_size(m);
	    b++, i++) {
		if (i % 8 == 0)
			fprintf(out, "\n   ");
		else if (i % 4 == 0)
			fprintf(out, " ");
		fprintf(out, " %02x", (unsigned char)*b);
	}
	fprintf(out, "\n");
}

ptrdiff_t
mdr_unpack_int8(struct mdr *m, int8_t *v)
{
	return mdr_unpack_uint8(m, (uint8_t *)v);
}

ptrdiff_t
mdr_unpack_int16(struct mdr *m, int16_t *v)
{
	return mdr_unpack_uint16(m, (uint16_t *)v);
}

ptrdiff_t
mdr_unpack_int32(struct mdr *m, int32_t *v)
{
	return mdr_unpack_uint32(m, (uint32_t *)v);
}

ptrdiff_t
mdr_unpack_int64(struct mdr *m, int64_t *v)
{
	return mdr_unpack_uint64(m, (uint64_t *)v);
}

ptrdiff_t
mdr_unpack_uint8(struct mdr *m, uint8_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint8_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = *(uint8_t *)m->pos;
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint16(struct mdr *m, uint16_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint16_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be16toh(*(uint16_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint32(struct mdr *m, uint32_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint32_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be32toh(*(uint32_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint64(struct mdr *m, uint64_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be64toh(*(uint64_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_float32(struct mdr *m, float *v)
{
	union {
		float    f;
		uint32_t i;
	} f;

	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(float)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	f.i = be32toh(*(uint32_t *)m->pos);
	*v = f.f;
	m->pos += sizeof(uint32_t);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_float64(struct mdr *m, double *v)
{
	union {
		double   f;
		uint64_t i;
	} f;

	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(float)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	f.i = be64toh(*(uint64_t *)m->pos);
	*v = f.f;
	m->pos += sizeof(uint64_t);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_bytes(struct mdr *m, char *bytes, uint64_t *bytes_sz)
{
	uint64_t avail;

	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	avail = *bytes_sz;

	if (m->buf_sz - mdr_tell(m) < sizeof(uint8_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*bytes_sz = *(uint8_t *)m->pos;
	if (*bytes_sz & 0x80) {
		if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		*bytes_sz = be64toh(*(uint64_t *)m->pos) & 0x7fffffffffffffff;

		if (m->buf_sz - (mdr_tell(m) + sizeof(uint64_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint64_t);
	} else {
		if (m->buf_sz - (mdr_tell(m) + sizeof(uint8_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint8_t);
	}

	memcpy(bytes, m->pos, MIN(avail, *bytes_sz));
	m->pos += *bytes_sz;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_bytes_ref(struct mdr *m, const char **src, uint64_t *bytes_sz)
{
	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint8_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*bytes_sz = *(uint8_t *)m->pos;
	if (*bytes_sz & 0x80) {
		if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		*bytes_sz = be64toh(*(uint64_t *)m->pos) & 0x7fffffffffffffff;

		if (m->buf_sz - (mdr_tell(m) + sizeof(uint64_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint64_t);
	} else {
		if (m->buf_sz - (mdr_tell(m) + sizeof(uint8_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint8_t);
	}

	*src = m->pos;
	m->pos += *bytes_sz;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_string(struct mdr *m, char *bytes, uint64_t *bytes_sz)
{
	uint64_t b, r;

	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (*bytes_sz < 1) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	/* Make room for \0 */
	b = *bytes_sz - 1;

	/*
	 * Get the size we would have unpacked if the bytes buffer
	 * was big enough.
	 */
	if ((r = mdr_unpack_bytes(m, bytes, &b)) == MDR_FAIL)
		return MDR_FAIL;

	bytes[MIN(*bytes_sz - 1, b)] = '\0';
	*bytes_sz = b + 1;
	return r;
}

ptrdiff_t
mdr_unpack_mdr_ref(struct mdr *m, struct mdr *dst)
{
	uint64_t sz;

	if (m == NULL || dst == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
		errno = ERANGE;
		return MDR_FAIL;
	}
	sz = be64toh(*(uint64_t *)m->pos);

	if (m->buf_sz - mdr_tell(m) < sz) {
		errno = ERANGE;
		return MDR_FAIL;
	}

	if (mdr_unpack_hdr(dst, MDR_F_NONE, m->pos, sz) == MDR_FAIL)
		return MDR_FAIL;
	m->pos += sz;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_mdr(struct mdr *m, struct mdr *dst, char *buf, size_t buf_sz)
{
	struct mdr ref;

	if (mdr_unpack_mdr_ref(m, &ref) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(&ref) > buf_sz) {
                errno = EOVERFLOW;
                return MDR_FAIL;
        }

	return mdr_copy(dst, buf, buf_sz, &ref);
}

ptrdiff_t
mdr_unpack_array_of(struct mdr *m, const char *type, int32_t *n,
    void *dst, uint64_t *max_item_sz)
{
	int       i;
	uint64_t  bits;
	uint32_t  packed_n;
	uint64_t  sz, saved_max_item_sz;
	char     *end;

	if (*(uint8_t *)m->pos & 0x80) {
		packed_n = be32toh(*(uint32_t *)m->pos) & 0x7fffffff;
		m->pos += sizeof(uint32_t);
	} else {
		packed_n = *(uint8_t *)m->pos;
		m->pos += sizeof(uint8_t);
	}

	if (max_item_sz != NULL) {
		saved_max_item_sz = *max_item_sz;
		*max_item_sz = 0;
	}

	for (i = 0; i < MIN(*n, packed_n); i++) {
		if (*type == 'i' || *type == 'u' || *type == 'f') {
			bits = strtoull(type + 1, &end, 10);
			if (bits == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}
		}

		switch (*type) {
		case 'i':
		case 'u':
			switch (bits) {
			case 8:
				if (mdr_unpack_uint8(m, (uint8_t *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 16:
				if (mdr_unpack_uint16(m, (uint16_t *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 32:
				if (mdr_unpack_uint32(m, (uint32_t *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (mdr_unpack_uint64(m, (uint64_t *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
			break;
		case 'f':
			switch (bits) {
			case 32:
				if (mdr_unpack_float32(m, (float *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (mdr_unpack_float64(m, (double *)dst + i)
				    == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
			break;
		case 'b':
			sz = saved_max_item_sz;
			if (mdr_unpack_bytes(m, ((char **)dst)[i], &sz)
			    == MDR_FAIL)
				return MDR_FAIL;
			if (sz > *max_item_sz)
				*max_item_sz = sz;
			break;
		case 's':
			sz = saved_max_item_sz;
			if (mdr_unpack_string(m, ((char **)dst)[i], &sz)
			    == MDR_FAIL)
				return MDR_FAIL;
			if (sz > *max_item_sz)
				*max_item_sz = sz;
			break;
		case 'm':
			if (mdr_unpack_mdr(m, (struct mdr *)dst + i, NULL, 0)
			    == MDR_FAIL) {
				*n = i;
				for (i = 0; i < *n; i++)
					mdr_free((struct mdr *)dst + i);
				return MDR_FAIL;
			}
		}
	}

	*n = i;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_(int argc, struct mdr *m, uint32_t allowed_flags, char *buf,
    size_t buf_sz, const char *spec, ...)
{
	va_list   ap;
	ptrdiff_t r;

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (mdr_unpack_hdr(m, allowed_flags, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	va_start(ap, spec);
	r = mdr_vunpackf(argc, 1, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	va_start(ap, spec);
	r = mdr_vunpackf(argc, 0, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpackf_(int argc, struct mdr *m, const char *spec, ...)
{
	va_list   ap;
	ptrdiff_t r;

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	va_start(ap, spec);
	r = mdr_vunpackf(argc, 1, m, spec, ap);
	va_end(ap);

	va_start(ap, spec);
	r = mdr_vunpackf(argc, 0, m, spec, ap);
	va_end(ap);

	if (r == MDR_FAIL)
		return MDR_FAIL;

	return mdr_tell(m);
}

ptrdiff_t
mdr_pack_echo(struct mdr *m, const char *echo)
{
	return mdr_pack(m, NULL, 0, MDR_F_NONE,
	    mdr_mkdcv(MDR_NS_MDR, MDR_NAME_MDR_ECHO, 0),
	    "sN", echo, -1);
}

ptrdiff_t
mdr_unpack_echo(struct mdr *m, char *buf, size_t sz, char *echo,
    size_t *echo_sz)
{
	return mdr_unpack(m, MDR_F_NONE, buf, sz, "sN", echo, echo_sz);
}
