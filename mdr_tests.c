#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mdr.h"
#include "util.h"

extern locale_t log_locale;
int             verbose = 0;

#define MDR_DCV_MDR_TEST_1 MDR_DCV(0x00000000, 0x0004, 0x0001)
#define MDR_DCV_MDR_TEST_2 MDR_DCV(0x00000000, 0x0004, 0x0002)
#define MDR_DCV_MDR_TEST_3 MDR_DCV(0x00000000, 0x0004, 0x0003)
#define MDR_DCV_MDR_TEST_4 MDR_DCV(0x00000000, 0x0004, 0x0004)
#define MDR_DCV_MDR_TEST_5 MDR_DCV(0x00000000, 0x0004, 0x0005)

struct mdr_def msgdef_test_0 = {
	MDR_DCV_MDR_TEST,
	"test.0",
	{
		MDR_S,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_0;

struct mdr_def msgdef_test_1 = {
	MDR_DCV_MDR_TEST_1,
	"test.1",
	{
		MDR_M,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_1;

struct mdr_def msgdef_test_2 = {
	MDR_DCV_MDR_TEST_2,
	"test.2",
	{
		MDR_B,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_2;

struct mdr_def msgdef_test_3 = {
	MDR_DCV_MDR_TEST_3,
	"test.3",
	{
		MDR_AU32,
		MDR_AS,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_3;

struct mdr_def msgdef_test_4 = {
	MDR_DCV_MDR_TEST_4,
	"test.3",
	{
		MDR_U64,
		MDR_I8,
		MDR_U16,
		MDR_B,
		MDR_S,
		MDR_F32,
		MDR_F64,
		MDR_S,
		MDR_AU8,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_4;

struct mdr_def msgdef_test_5 = {
	MDR_DCV_MDR_TEST_5,
	"test.3",
	{
		MDR_B,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_5;

const struct mdr_spec *msg_mdr_echo;
const struct mdr_spec *msg_mdr_ping;


struct test_status
{
	char *msg;
	enum {
		OK = 0,
		FAIL,
		FLAKED,
		SKIPPED
	} status;
} test_status;

const char *status_description[] = {
	"OK",
	"FAIL",
	"FLAKED",
	"SKIPPED"
};


struct test_status *
success()
{
	test_status.status = OK;
	test_status.msg = NULL;
	return &test_status;
}

struct test_status *
skipped()
{
	test_status.status = SKIPPED;
	test_status.msg = NULL;
	return &test_status;
}

struct test_status *
fail(int status, int e, const char *fn, int line, const char *msg, ...)
{
	va_list  ap;
	char    *s;

	va_start(ap, msg);
	if (vasprintf(&s, msg, ap) == -1)
		err(1, "vasprintf");
	va_end(ap);

	test_status.status = status;
	if (asprintf(&test_status.msg, "%s %s (errno=%d; %s:%d)", s,
	    (e) ? strerror_l(e, log_locale) : "", e, fn, line) == -1)
		err(1, "asprintf");
	free(s);
	return &test_status;
}
#define ERR(e, msg, ...) fail(FAIL, e, __func__, __LINE__, msg __VA_OPT__(,) __VA_ARGS__)
#define FLAKY(e, msg, ...) fail(FLAKED, e, __func__, __LINE__, msg __VA_OPT__(,) __VA_ARGS__)

struct test_status *
test_long_str()
{
	int        i;
	uint64_t   r;
	char       str[1024];
	struct mdr in, out;

	struct mdr_in  m_in[1];
	struct mdr_out m_out[1];

	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = str;
	m_in[0].v.s.sz = -1;
	if ((r = mdr_pack(&in, NULL, 0, msg_test_0, MDR_F_NONE, m_in, 1))
	    == MDR_FAIL)
		return ERR(errno, "mdr_pack_hdr");

	if (r - mdr_hdr_size(MDR_F_NONE) != 1032)
		return ERR(0, "expected message payload 1032");

	if ((r = mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_test_0, MDR_F_NONE, m_out, 1)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack failed");
	mdr_free(&in);

	if (m_out[0].type != MDR_S)
		return ERR(0, "unexpected type returned instead of MDR_S");

	if (strcmp(str, m_out[0].v.s.bytes) != 0)
		return ERR(errno, "unpacked string is not what we expect");

	return success();
}

struct test_status *
test_pack_mdr()
{
	char            in_str_buf[64], in_buf[64];
	char            str[32] = "hey hey hey";
	struct mdr      in_str, in, out, out_str;
	struct mdr_in   m_in[1];
	struct mdr_out  m_out[1], m_out_str[1];

	/* Create inner mdr, containing a string */
	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = str;
	m_in[0].v.s.sz = -1;
	if (mdr_pack(&in_str, in_str_buf, sizeof(in_str_buf), msg_test_0,
	    MDR_F_NONE, m_in, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	m_in[0].type = MDR_M;
	m_in[0].v.m = &in_str;
	if (mdr_pack(&in, in_buf, sizeof(in_buf),
	    msg_test_1, MDR_F_NONE, m_in, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack nested");

	if (mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_test_1, MDR_F_NONE, m_out, 1) == MDR_FAIL)
		return ERR(errno, "mdr_unpack nested");

	if (m_out[0].type != MDR_M)
		return ERR(0, "unexpected type returned instead of MDR_M");

	if (mdr_unpack(&out_str,
	    (void *)mdr_buf(&m_out[0].v.m), mdr_size(&m_out[0].v.m),
	    msg_test_0, MDR_F_NONE, m_out_str, 1) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_str");

	if (m_out_str[0].type != MDR_S)
		return ERR(0, "unexpected type returned instead of MDR_S");

	if (strcmp(str, m_out_str[0].v.s.bytes) != 0)
		return ERR(0, "strings don't match");

	return success();
}

struct test_status *
test_pack_reserved_bytes()
{
	uint64_t         r;
	char             buf[64];
	char             str[32] = "hey hey hey";
	char            *dst;
	struct mdr      in, out;
	struct mdr_in   m_in[1];
	struct mdr_out  m_out[1];

	/* Create an mdr in which we reserve space for a string */
	m_in[0].type = MDR_RSVB;
	m_in[0].v.rsvb.dst = &dst;
	m_in[0].v.rsvb.sz = strlen(str);
	if (mdr_pack(&in, buf, sizeof(buf), msg_test_2, MDR_F_NONE,
	    m_in, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack nested");

	/* Copy our bytes in the reserved space */
	memcpy(dst, str, strlen(str));

	if ((r = mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_test_2, MDR_F_NONE, m_out, 1)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack failed");

	if (m_out[0].type != MDR_B)
		return ERR(0, "unexpected type returned instead of MDR_B");
	if (m_out[0].v.b.sz != strlen(str))
		return ERR(0, "unexpected length of bytes returned");

	if (memcmp(str, m_out[0].v.b.bytes, strlen(str)) != 0)
		return ERR(0, "bytes mismatch");

	/* Try again but with zero space */
	m_in[0].type = MDR_RSVB;
	m_in[0].v.rsvb.dst = &dst;
	m_in[0].v.rsvb.sz = 0;
	if (mdr_pack(&in, buf, sizeof(buf), msg_test_2, MDR_F_NONE,
	    m_in, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack nested");
	if ((r = mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_test_2, MDR_F_NONE, m_out, 1)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack failed");
	if (m_out[0].v.b.sz != 0)
		return ERR(0, "mdr_unpack zero bytes returned non-zero");

	return success();
}

struct test_status *
test_long_tail_bytes()
{
	uint64_t   r;
	struct mdr in, out;
	char       buf[4096];
	char       stra[1024];
	char       strb[128];
	char       strab_expected[2048], strab[2048];
	int        i, j;

	for (i = 0; i < sizeof(stra) - 1; i++) {
		stra[i] = 'a';
		strab_expected[i] = 'a';
	}
	stra[i] = '\0';

	for (j = 0; j < sizeof(strb) - 1; j++, i++) {
		strb[j] = 'b';
		strab_expected[i] = 'b';
	}
	strb[j] = '\0';
	strab_expected[i] = '\0';

	if (mdr_pack_hdr(&in, buf, sizeof(buf), msg_mdr_ping,
	    MDR_F_TAIL_BYTES) == MDR_FAIL)
		return ERR(errno, "mdr_pack_hdr");

	/*
	 * Make space for tail bytes after the mdr payload,
	 * twice for each of our strings
	 */
	if ((r = mdr_add_tail_bytes(&in, strlen(stra))) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes stra");
	if ((r = mdr_add_tail_bytes(&in, strlen(strb))) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes strb");

	/* Fill the reserved space with our strings */
	memcpy(buf + r, stra, strlen(stra));
	memcpy(buf + r + strlen(stra), strb, strlen(strb));

	/* Test decoding when we disallow tail bytes */
	r = mdr_unpack_hdr(&out, MDR_F_NONE, (void *)mdr_buf(&in),
	    mdr_size(&in));
	if (r != MDR_FAIL || errno != EACCES)
		return ERR(0, "mdr_unpack_hdr should have failed with EACCES");

	if (mdr_unpack_hdr(&out, MDR_F_TAIL_BYTES, (void *)mdr_buf(&in),
	    mdr_size(&in)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_hdr");

	/* Copy all tail bytes after payload into strab */
	bzero(strab, sizeof(strab));
	memcpy(strab, mdr_buf(&out) + mdr_tell(&out), mdr_tail_bytes(&out));

	/* Then compare */
	if (memcmp(strab, strab_expected, mdr_tail_bytes(&out)) != 0)
		return ERR(0, "bytes don't match");

	return success();
}

struct test_status *
test_limits()
{
	uint64_t   n;
	struct mdr echo;
	char       str[1];

	if (mdr_pack_hdr(&echo, NULL, 0, msg_test_5,
	    MDR_F_TAIL_BYTES) == MDR_FAIL)
		return ERR(errno, "mdr_pack_hdr");

	n = (PTRDIFF_MAX -
	    (mdr_hdr_size(mdr_flags(&echo)) + sizeof(uint64_t))) + 1;

	if (mdr_pack_bytes(&echo, str, n) != MDR_FAIL)
		return ERR(0, "mdr_pack_bytes: expected EOVERFLOW, "
		    "but it succeeded");
	if (errno != EOVERFLOW)
		return ERR(errno,
		    "mdr_pack_bytes: expected EOVERFLOW, got %d\n", errno);

	// TODO: we should have a way to retry only what failed but the spec
	// already moved on.
	mdr_rewind(&echo);

	n = PTRDIFF_MAX -
	    (mdr_hdr_size(mdr_flags(&echo)) + sizeof(uint64_t) + 1);
	if (mdr_pack_bytes(&echo, str, n) != MDR_FAIL)
		return ERR(0, "mdr_pack_bytes: expected ENOMEM, "
		    "but it succeeded");
	if (errno != ENOMEM)
		return ERR(0, "mdr_pack_bytes(b): expected ENOMEM, "
		    "got %d\n", errno);

	if (mdr_add_tail_bytes(&echo, UINT64_MAX) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes");
	if (mdr_add_tail_bytes(&echo, 1) != MDR_FAIL)
		return ERR(0, "mdr_add_tail_bytes: expected EOVERFLOW, "
		    "but it succeeded");
	if (errno != EOVERFLOW)
		return ERR(0, "mdr_add_tail_bytes: expected EOVERFLOW, "
		    "got %d\n", errno);

	mdr_free(&echo);

	return success();
}

struct test_status *
test_echo()
{
	int            i;
	struct mdr     in, out;
	char           str[1024];
	struct mdr_in  m_in[1];
	struct mdr_out m_out[1];

	bzero(str, sizeof(str));
	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';

	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = str;
	m_in[0].v.s.sz = -1;
	if (mdr_pack(&in, NULL, 0, msg_mdr_echo, MDR_F_NONE, m_in, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack_echo");

	if (mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_mdr_echo, MDR_F_NONE, m_out, 1) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_echo");

	if (strcmp(m_out[0].v.s.bytes, str) != 0)
		return ERR(0, "strings don't match");

	mdr_free(&in);

	return success();
}

struct test_status *
test_pack_array()
{
	struct mdr       in, out;
	char             buf[1024];
	uint64_t         r;

	uint32_t         a_u32[3] = { 0, 1, 2 };
	uint32_t         a_u32_out[3] = { 0, 0, 0 };

	const char      *a_s[] = { "string1", "string2", NULL };
	const char      *a_s_out[3] = { "", "", "" };

	struct mdr_in    m_in[2];
	struct mdr_out   m_out[2];

	m_in[0].type = MDR_AU32;
	m_in[0].v.au32.items = a_u32;
	m_in[0].v.au32.length = 3;
	m_in[1].type = MDR_AS;
	m_in[1].v.as.items = a_s;
	m_in[1].v.as.length = -1;
	r = mdr_pack(&in, buf, sizeof(buf), msg_test_3, MDR_F_NONE, m_in, 2);
	if (r == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	r = mdr_unpack(&out, buf, r, msg_test_3, MDR_F_NONE, m_out, 2);
	if (r == MDR_FAIL)
		return ERR(errno, "mdr_unpack");

	if (m_out[0].type != MDR_AU32)
		return ERR(0, "first field is not MDR_AU32 as expected");
	if (m_out[0].v.au32.length != 3)
		return ERR(0, "first array does not contain 3 items");

	if (mdr_out_array_u32(&m_out[0].v.au32, a_u32_out, 3) == MDR_FAIL)
		return ERR(errno, "mdr_out_array_u32");

	if (memcmp(a_u32, a_u32_out, sizeof(a_u32)) != 0)
		return ERR(0, "first array has wrong content");


	if (m_out[1].type != MDR_AS)
		return ERR(0, "second field is not MDR_AS as expected");

	if (mdr_out_array_s(&m_out[1].v.as, a_s_out, 3) == MDR_FAIL)
		return ERR(errno, "mdr_out_array_s");

	if (strcmp(a_s[0], a_s_out[0]) != 0)
		return ERR(0, "a_s_out[0] has wrong content");
	if (strcmp(a_s[1], a_s_out[1]) != 0)
		return ERR(0, "a_s_out[1] has wrong content");
	if (a_s_out[2] != NULL)
		return ERR(0, "a_s_out[2] should be NULL");

	return success();
}

struct test_status *
test_encoding()
{
	struct mdr  in, out;
	char        buf[1024];
	char       *longstr = "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg";
	uint8_t     longarray[128];
	uint8_t     longarray_out[128];
	uint64_t    longarray_sz = sizeof(longarray) / sizeof(uint8_t);
	const char encoded[] =
	    "\x00\x00\x00\x00\x00\x00\x01\x45" /* size */
	    "\x00\x00\x00\x00"                 /* flags */
	    "\x00\x00\x00\x00"                 /* domain */
	    "\x00\x04"                         /* code */
	    "\x00\x04"                         /* variant */
	    "\x00\x00\x00\x00\x00\x00\x00\x6f" /* u64 */
	    "\x80"                             /* i8 */
	    "\x00\x6f"                         /* u16 */
	    "\x04\x61\x6c\x6c\x6f"             /* b (allo) */
	    "\x07\x73\x74\x72\x69\x6e\x67\x00" /* s (string) */
	    "\xc2\xde\x38\xd5"                 /* f32 */
	    "\xc0\xc5\xb3\x8e\x38\xda\x3c\x21" /* f64 */
	    "\x80\x00\x00\x00\x00\x00\x00\x81" /* sN (long string - 128x 'g') */
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x67\x67\x67\x67\x67\x67\x67\x67"
	    "\x00"
	    "\x80\x00\x00\x80"                 /* Au8 (array of 128) */
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    ;
	size_t encoded_length = sizeof(encoded) - 1;

	struct mdr_in  m_in[9];
	struct mdr_out m_out[9];

	// TODO: test value overflow/boundaries

	bzero(longarray, sizeof(longarray));

	m_in[0].type = MDR_U64;
	m_in[0].v.u64 = 111;
	m_in[1].type = MDR_I8;
	m_in[1].v.u64 = -128;
	m_in[2].type = MDR_U16;
	m_in[2].v.u16 = 111;
	m_in[3].type = MDR_B;
	m_in[3].v.b.bytes = "allo";
	m_in[3].v.b.sz = 4;
	m_in[4].type = MDR_S;
	m_in[4].v.s.bytes = "string";
	m_in[4].v.s.sz = -1;
	m_in[5].type = MDR_F32;
	m_in[5].v.f32 = -111.111;
	m_in[6].type = MDR_F64;
	m_in[6].v.f64 = -11111.11111;
	m_in[7].type = MDR_S;
	m_in[7].v.s.bytes = longstr;
	m_in[7].v.s.sz = -1;
	m_in[8].type = MDR_AU8;
	m_in[8].v.au8.length = longarray_sz;
	m_in[8].v.au8.items = longarray;
	if (mdr_pack(&in, buf, sizeof(buf), msg_test_4, MDR_F_NONE,
	    m_in, 9) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	if (mdr_size(&in) != encoded_length)
		return ERR(0, "encoded length should be %lu but was %lu",
		    encoded_length, mdr_size(&in));

	if (memcmp(mdr_buf(&in), encoded, encoded_length) != 0)
		return ERR(0, "encoding mismatch");

	if (mdr_unpack(&out, (void *)mdr_buf(&in), mdr_size(&in),
	    msg_test_4, MDR_F_NONE, m_out, 9) == MDR_FAIL)
		return ERR(errno, "mdr_unpack");

	if (mdr_size(&out) != encoded_length)
		return ERR(0, "encoded length should be %lu but was %lu",
		    encoded_length, mdr_size(&out));

	if (m_out[0].v.u64 != 111)
		return ERR(0, "decoded u64 is not the right value");
	if (m_out[1].v.i8 != -128)
		return ERR(0, "decoded i8 is not the right value");
	if (m_out[2].v.u16 != 111)
		return ERR(0, "decoded u16 is not the right value");

	if (m_out[3].v.b.sz != strlen("allo"))
		return ERR(0, "decoded bytes size mismatch");
	if (memcmp(m_out[3].v.b.bytes, "allo", m_out[3].v.b.sz) != 0)
		return ERR(0, "decoded bytes content mismatch");

	if (strcmp(m_out[4].v.s.bytes, "string") != 0)
		return ERR(0, "decoded string is not the right value");

	/*
	 * Equality tests on floats are technically a bug but those have
	 * been shown to match
	 */
	if (m_out[5].v.f32 != -111.111f)
		return ERR(0, "decoded f32 is not the right value; "
		    "expected=%f, got=%f", -111.111, m_out[5].v.f32);
	if (m_out[6].v.f64 != -11111.11111)
		return ERR(0, "decoded f64 is not the right value; "
		    "expected=%f, got=%f", -11111.11111, m_out[6].v.f64);

	if (strcmp(m_out[7].v.s.bytes, longstr) != 0)
		return ERR(0, "decoded long string mismatch");

	if (mdr_out_array_length(&m_out[8].v.au8) != longarray_sz)
		return ERR(0, "decoded longarray size mismatch");
	if (mdr_out_array_u8(&m_out[8].v.au8, longarray_out, 128) == MDR_FAIL)
		return ERR(0, "failed to read longarray");
	if (memcmp(longarray, longarray_out, longarray_sz) != 0)
		return ERR(0, "decoded longarray content mismatch");

	return success();
}

struct mdr_test {
	char                description[256];
	int                 default_set;
	struct test_status *(*fn)();
} tests[] = {
	{
		"encoding",
		1,
		&test_encoding
	},
	{
		"pack long strings",
		1,
		&test_long_str
	},
	{
		"echo mdr",
		1,
		&test_echo
	},
	{
		"long tail bytes",
		1,
		&test_long_tail_bytes
	},
	{
		"limit",
		1,
		&test_limits
	},
	{
		"pack nested messages",
		1,
		&test_pack_mdr
	},
	{
		"pack reserved space",
		1,
		&test_pack_reserved_bytes
	},
	{
		"pack arrays",
		1,
		&test_pack_array
	}
};

void
usage()
{
	fprintf(stderr, "Usage: mdr_tests [options] [test substring]\n"
	    "\t-h\t\t\tPrints this help\n"
	    "\t-d\t\t\tDebug output\n");
}

int
main(int argc, char **argv)
{
	struct mdr_test    *t;
	int                 status = 0;
	char                opt;
	struct test_status *s;

	while ((opt = getopt(argc, argv, "hd")) != -1) {
		switch (opt) {
			case 'h':
				usage();
				exit(0);
			case 'd':
				verbose = 1;
				break;
			default:
				usage();
				exit(1);
		}
	}

	if (optind > argc) {
		usage();
		exit(1);
	}

	if ((log_locale = newlocale(LC_CTYPE_MASK, "C", 0)) == 0)
		err(1, "newlocale");

	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");
	if ((msg_test_0 = mdr_register_spec(&msgdef_test_0)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_1 = mdr_register_spec(&msgdef_test_1)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_2 = mdr_register_spec(&msgdef_test_2)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_3 = mdr_register_spec(&msgdef_test_3)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_4 = mdr_register_spec(&msgdef_test_4)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_5 = mdr_register_spec(&msgdef_test_5)) == NULL)
		err(1, "mdr_register_spec");
	msg_mdr_echo = mdr_registry_get(MDR_DCV_MDR_ECHO);
	msg_mdr_ping = mdr_registry_get(MDR_DCV_MDR_PING);

	for (t = tests; t->fn != NULL; t++) {
		if (argc == optind && !t->default_set)
			continue;

		if (argc > optind &&
		    strstr(t->description, argv[optind]) == NULL)
			continue;

		s = t->fn();
		printf("[%s] %s\n", status_description[s->status],
		    t->description);
		if (s->msg && (s->status == SKIPPED))
			continue;
		if (s->msg && (s->status == FAIL || s->status == FLAKED)) {
			status = 1;
			printf("\n%s\n\n", s->msg);
			free(s->msg);
		}
	}
	return status;
}
