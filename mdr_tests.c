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

struct mdr_spec msg_test_0 = {
	MDR_DCV(0x00000000, 0x0003, 0x0000), { MDR_S }
};

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
	char       str[1024], str2[1000];
	uint64_t   len = sizeof(str2);
	struct mdr in, out;

	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	if ((r = mdr_pack(&in, NULL, 0, MDR_F_NONE,
	    msg_test_0.dcv, "sN", str, -1)) == MDR_FAIL)
		return ERR(errno, "mdr_pack_hdr");

	if (r - mdr_hdr_size(MDR_F_NONE) != 1031)
		return ERR(0, "expected message payload 1031");

	if ((r = mdr_unpack(&out, MDR_F_NONE,
	    (void *)mdr_buf(&in), mdr_size(&in), "sN", str2, &len)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack failed");
	mdr_free(&in);

	for (i = 0; i < sizeof(str2) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	if (strlen(str2) != strlen(str))
		return ERR(errno, "unpacked strings are not the same length");
	if (strcmp(str2, str) != 0)
		return ERR(errno, "unpacked string is not what we expect");

	return success();
}

struct test_status *
test_pack_mdr()
{
	char       in_str_buf[64], in_buf[64];
	char       str[32] = "hey hey hey";
	char       str_out[32] = "";
	uint64_t   len = sizeof(str_out);
	struct mdr in_str, in, out, out_str;

	/* Create inner mdr, containing a string */
	if (mdr_pack(&in_str, in_str_buf, sizeof(in_str_buf), MDR_F_NONE,
	    msg_test_0.dcv, "sN", str, -1) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	if (mdr_pack(&in, in_buf, sizeof(in_buf), MDR_F_NONE,
	    msg_test_0.dcv, "m", &in_str) == MDR_FAIL)
		return ERR(errno, "mdr_pack nested");

	if (mdr_unpack(&out, MDR_F_NONE,
	    (void *)mdr_buf(&in), mdr_size(&in), "m", &out_str) == MDR_FAIL)
		return ERR(errno, "mdr_unpack nested");

	if (mdr_unpack_string(&out_str, str_out, &len) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_string");

	if (strcmp(str, str_out) != 0)
		return ERR(0, "strings don't match");

	return success();
}

struct test_status *
test_pack_space()
{
	uint64_t    r, len;
	char        buf[64];
	char        str[32] = "hey hey hey";
	const char *ref;
	char       *dst;
	struct mdr  in, out;

	/* Create an mdr in which we reserve space for a string */
	if ((r = mdr_pack(&in, buf, sizeof(buf), MDR_F_NONE,
	    msg_test_0.dcv, "rN", &dst, strlen(str))) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	/* Copy our string in the reserved space */
	memcpy(dst, str, strlen(str));

	if (mdr_unpack_hdr(&out, MDR_F_NONE, (void *)mdr_buf(&in),
	    mdr_size(&in)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_hdr");

	/* Get a pointer to our bytes */
	if ((r = mdr_unpack_bytes_ref(&out, &ref, &len)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_bytes_ref");

	if (memcmp(str, ref, strlen(str)) != 0)
		return ERR(0, "bytes ref mismatch");

	/* Try again but with zero space */
	if ((r = mdr_pack(&in, buf, sizeof(buf), MDR_F_NONE,
	    msg_test_0.dcv, "rN", &dst, 0)) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	len = sizeof(str);
	if ((r = mdr_unpack(&out, MDR_F_NONE,
	    (void *)mdr_buf(&in), mdr_size(&in), "bN", &str, &len)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack zero bytes");

	if (len != 0)
		return ERR(errno, "mdr_unpack zero bytes returned bytes");

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

	if (mdr_pack_hdr(&in, buf, sizeof(buf), MDR_F_TAIL_BYTES,
	    msg_test_0.dcv) == MDR_FAIL)
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
	r = mdr_unpack_hdr(&out, MDR_F_NONE,
	    (void *)mdr_buf(&in), mdr_size(&in));
	if (r != MDR_FAIL || errno != EACCES)
		return ERR(0, "mdr_unpack_hdr should have failed with EACCES");

	if (mdr_unpack_hdr(&out, MDR_F_TAIL_BYTES,
	    (void *)mdr_buf(&in), mdr_size(&in)) == MDR_FAIL)
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

	if (mdr_pack_hdr(&echo, NULL, 0, MDR_F_TAIL_BYTES,
	    msg_test_0.dcv) == MDR_FAIL)
		return ERR(errno, "mdr_pack_hdr");

	n = (PTRDIFF_MAX -
	    (mdr_hdr_size(mdr_flags(&echo)) + sizeof(uint64_t))) + 1;

	if (mdr_pack_bytes(&echo, str, n) != MDR_FAIL)
		return ERR(0, "mdr_pack_bytes: expected EOVERFLOW, "
		    "but it succeeded");
	if (errno != EOVERFLOW)
		return ERR(errno,
		    "mdr_pack_bytes: expected EOVERFLOW, got %d\n");

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
	int        i;
	struct mdr src, dst;
	char       str[1024];
	size_t     str_sz;

	bzero(str, sizeof(str));
	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';

	if (mdr_pack_echo(&src, str) == MDR_FAIL)
		return ERR(errno, "mdr_pack_echo");

	bzero(str, sizeof(str));

	str_sz = sizeof(str);

	if (mdr_unpack_echo(&dst, (void *)mdr_buf(&src), mdr_size(&src),
	    str, &str_sz) == MDR_FAIL)
		return ERR(errno, "mdr_unpack_echo");
	mdr_free(&src);

	return success();
}

struct test_status *
test_pack_array()
{
	struct mdr   in, out;
	char         buf[1024];
	uint64_t     r;

	uint32_t     a_u32[3] = { 0, 1, 2 };
	uint32_t     a_u32_n = 3;
	uint32_t     a_u32_out[3] = { 0, 1, 2 };

	char        *a_s[] = { "string1", "string2", NULL };
	uint32_t     a_s_n = 3;
	char       **a_s_out = strarray_alloc(3, 16);
	uint64_t     a_s_out_sz = 16;

	char        *a_b[] = { "bytes1", "bytes2", "bytes3" };
	uint32_t     a_b_n = 3;
	char       **a_b_out = strarray_alloc(3, 6);
	uint64_t     a_b_out_sz = 6;

	r = mdr_pack(&in, buf, sizeof(buf), MDR_F_NONE,
	    msg_test_0.dcv, "Au32:AsN:AbN",
	    a_u32_n, a_u32,
	    -1, a_s, -1,
	    3, a_b, 6);
	if (r == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	r = mdr_unpack(&out, MDR_F_NONE, buf, r, "Au32:AsN:AbN",
	    &a_u32_n, a_u32_out,
	    &a_s_n, a_s_out, &a_s_out_sz,
	    &a_b_n, a_b_out, &a_b_out_sz);
	if (r == MDR_FAIL)
		return ERR(errno, "mdr_unpack");
	if (a_s_out_sz != strlen("string1") + 1)
		return ERR(0, "a_s_out_sz should have been %d, was %lu",
		    strlen("string1") + 1, a_s_out_sz);
	if (a_b_out_sz != strlen("bytes3"))
		return ERR(0, "a_b_out_sz should have been %d, was %lu",
		    strlen("bytes3"), a_b_out_sz);
	free(a_s_out);
	free(a_b_out);

	return success();
}

struct test_status *
test_encoding()
{
	struct mdr  in, out;
	char        buf[1024];
	uint64_t    u64;
	uint16_t    u16;
	int8_t      i8;
	char        dbytes[1024];
	uint64_t    dlen = 0;
	char        dstr[1024];
	uint64_t    dstr_len;
	char        dlongstr[1024];
	uint64_t    dlongstr_len = sizeof(dlongstr);
	float       f32;
	double      f64;
	char       *longstr = "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg";
	uint8_t     longarray[128];
	uint64_t    longarray_sz = sizeof(longarray) / sizeof(uint8_t);
	const char encoded[] =
	    "\x00\x00\x00\x00\x00\x00\x01\x43" /* size */
	    "\x00\x00\x00\x00"                 /* flags */
	    "\x00\x00\x00\x00"                 /* namespace */
	    "\x00\x03"                         /* name */
	    "\x00\x00"                         /* variant */
	    "\x00\x00\x00\x00\x00\x00\x00\x6f" /* u64 */
	    "\x80"                             /* i8 */
	    "\x00\x6f"                         /* u16 */
	    "\x04\x61\x6c\x6c\x6f"             /* bN (allo) */
	    "\x06\x73\x74\x72\x69\x6e\x67"     /* sN (string) */
	    "\xc2\xde\x38\xd5"                 /* f32 */
	    "\xc0\xc5\xb3\x8e\x38\xda\x3c\x21" /* f64 */
	    "\x80\x00\x00\x00\x00\x00\x00\x80" /* sN (long string - 128x 'g') */
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

	// TODO: test value overflow/boundaries

	bzero(longarray, sizeof(longarray));

#define mdr_string(str, len) str,(uint64_t)len
	if (mdr_pack(&in, buf, sizeof(buf), MDR_F_NONE,
	    msg_test_0.dcv, "u64:i8:u16:bN:sN:f32:f64:sN:Au8",
	    // TODO: we need helper macros here, this is horrible
	    // e.g. mdr_u64(), mdr_sN("allo", 4)
	    /// Or screw stdarg and just validate the sequence of
	    // mdr_pack_* by keeping the format in the mdr struct and
	    // making sure we sent everything.
	    (uint64_t)111,
	    -128,
	    111,
	    mdr_string("allo", 4),
	    //"allo", (uint64_t)4,
	    "string", (int64_t)-1,
	    -111.111,
	    -11111.11111,
	    longstr, (int64_t)-1,
	    longarray_sz, longarray) == MDR_FAIL)
		return ERR(errno, "mdr_pack");
	if (mdr_size(&in) != encoded_length)
		return ERR(0, "encoded length should be %lu but was %lu",
		    encoded_length, mdr_size(&in));

	if (memcmp(mdr_buf(&in), encoded, encoded_length) != 0)
		return ERR(0, "encoding mismatch");

	dlen = sizeof(dbytes);
	dstr_len = sizeof(dstr);
	if (mdr_unpack(&out, MDR_F_NONE, (void *)mdr_buf(&in),
	    mdr_size(&in), "u64:i8:u16:bN:sN:f32:f64:sN:Au8",
	    &u64,
	    &i8,
	    &u16,
	    dbytes, &dlen,
	    dstr, &dstr_len,
	    &f32,
	    &f64,
	    dlongstr, &dlongstr_len,
	    &longarray_sz, longarray) == MDR_FAIL)
		return ERR(errno, "mdr_unpack");
	if (mdr_size(&out) != encoded_length)
		return ERR(0, "encoded length should be %lu but was %lu",
		    encoded_length, mdr_size(&out));

	if (u64 != 111)
		return ERR(0, "decoded u64 is not the right value");
	if (i8 != -128)
		return ERR(0, "decoded i8 is not the right value");
	if (u16 != 111)
		return ERR(0, "decoded u16 is not the right value");
	if (memcmp(dbytes, "allo", dlen) != 0)
		return ERR(0, "decoded bytes are not the right values");
	if (strcmp(dstr, "string") != 0)
		return ERR(0, "decoded string is not the right value");
	if (strcmp(dlongstr, longstr) != 0)
		return ERR(0, "decoded string is not the right value");

	/*
	 * Equality tests on floats are technically a bug but those have
	 * been shown to match
	 */
	if (f32 != -111.111f)
		return ERR(0, "decoded f32 is not the right value; "
		    "expected=%f, got=%f", -111.111, f32);
	if (f64 != -11111.11111)
		return ERR(0, "decoded f64 is not the right value; "
		    "expected=%f, got=%f", -11111.11111, f64);

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
		&test_pack_space
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
