/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mdr/mdr.h>
#include <mdr/util.h>

int verbose = 0;

#define MDR_DCV_MDR_TEST_1 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 1)
#define MDR_DCV_MDR_TEST_2 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 2)
#define MDR_DCV_MDR_TEST_3 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 3)
#define MDR_DCV_MDR_TEST_4 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 4)
#define MDR_DCV_MDR_TEST_5 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 5)
#define MDR_DCV_MDR_TEST_6 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 6)
#define MDR_DCV_MDR_TEST_7 MDR_MAKE_VARIANT(MDR_DCV_MDR_TEST, 7)

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
	"test.4",
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
	"test.5",
	{
		MDR_B,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_5;

struct mdr_def msgdef_test_6 = {
	MDR_DCV_MDR_TEST_6,
	"test.6",
	{
		MDR_RSEQ, MDR_U8, MDR_S, MDR_END_RSEQ,
		MDR_RSEQ, MDR_I16, MDR_AU32, MDR_END_RSEQ,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_6;

/*
 * Wide repeated sequence exercising the full set of packable element
 * types: every scalar width, a byte blob, and a representative spread of
 * array kinds.
 */
struct mdr_def msgdef_test_7 = {
	MDR_DCV_MDR_TEST_7,
	"test.7",
	{
		MDR_RSEQ,
		MDR_U32, MDR_U64, MDR_I8, MDR_I32, MDR_I64, MDR_F32, MDR_F64,
		MDR_B, MDR_AU8, MDR_AI16, MDR_AF64, MDR_AS,
		MDR_END_RSEQ,
		MDR_LAST
	}
};
const struct mdr_spec *msg_test_7;

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


static struct test_status *
success()
{
	test_status.status = OK;
	test_status.msg = NULL;
	return &test_status;
}

static struct test_status *
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
	    (e) ? strerror(e) : "", e, fn, line) == -1)
		err(1, "asprintf");
	free(s);
	return &test_status;
}
#define ERR(e, msg, ...) fail(FAIL, e, __func__, __LINE__, msg __VA_OPT__(,) __VA_ARGS__)
#define FLAKY(e, msg, ...) fail(FLAKED, e, __func__, __LINE__, msg __VA_OPT__(,) __VA_ARGS__)

static struct test_status *
test_long_str()
{
	int             i;
	uint64_t        r;
	char            str[1024];
	struct pmdr     pm;
	struct umdr     um;
	struct pmdr_vec pv[1];
	struct umdr_vec uv[1];

	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	if (pmdr_init(&pm, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");

	pv[0].type = MDR_S;
	pv[0].v.s = str;
	if ((r = pmdr_pack(&pm, msg_test_0, pv, 1)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (r - mdr_hdr_size(MDR_FNONE) != 1032)
		return ERR(0, "expected message payload 1032");

	if ((r = umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm),
	    MDR_FNONE)) == MDR_FAIL)
		return ERR(errno, "umdr_init");

	if ((r = umdr_unpack(&um, msg_test_0, uv, 1)) == MDR_FAIL)
		return ERR(errno, "mdr_unpack failed");

	if (uv[0].type != MDR_S)
		return ERR(0, "unexpected type returned instead of MDR_S");

	if (strcmp(str, uv[0].v.s.bytes) != 0)
		return ERR(errno, "unpacked string is not what we expect");

	pmdr_free(&pm);
	return success();
}

static struct test_status *
test_pack_mdr()
{
	char            str[32] = "hey hey hey";
	struct pmdr     pm, pm_str;
	struct pmdr_vec pv[1];
	struct umdr     um;
	struct umdr_vec uv[1], uv_str[1];

	/* Create inner mdr, containing a string */
	if (pmdr_init(&pm_str, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_S;
	pv[0].v.s = str;
	if (pmdr_pack(&pm_str, msg_test_0, pv, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack/pm_str");

	if (pmdr_init(&pm, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_M;
	pv[0].v.pmdr = &pm_str;
	if (pmdr_pack(&pm, msg_test_1, pv, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack/pm");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm),
	    MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "umdr_init");

	if (umdr_unpack(&um, msg_test_1, uv, 1) == MDR_FAIL)
		return ERR(errno, "umdr_unpack/um");

	if (uv[0].type != MDR_M)
		return ERR(0, "unexpected type returned instead of MDR_M");

	if (umdr_unpack(&uv[0].v.m, msg_test_0, uv_str, 1) == MDR_FAIL)
		return ERR(errno, "umdr_unpack/nested");

	if (uv_str[0].type != MDR_S)
		return ERR(0, "unexpected type returned instead of MDR_S");

	if (strcmp(str, uv_str[0].v.s.bytes) != 0)
		return ERR(0, "strings don't match");

	pmdr_free(&pm);
	pmdr_free(&pm_str);
	return success();
}

static struct test_status *
test_pack_reserved_bytes()
{
	uint64_t         r;
	char             buf[64];
	char             str[32] = "hey hey hey";
	void            *dst;
	struct pmdr      pm;
	struct pmdr_vec  pv[1];
	struct umdr      um;
	struct umdr_vec  uv[1];

	/* Create an mdr in which we reserve space for a string */
	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_RSVB;
	pv[0].v.rsvb.dst = &dst;
	pv[0].v.rsvb.sz = strlen(str);
	if (pmdr_pack(&pm, msg_test_2, pv, 1) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	/* Copy our bytes in the reserved space */
	memcpy(dst, str, strlen(str));

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm),
	    MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if ((r = umdr_unpack(&um, msg_test_2, uv, 1)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	if (uv[0].type != MDR_B)
		return ERR(0, "unexpected type returned instead of MDR_B");
	if (uv[0].v.b.sz != strlen(str))
		return ERR(0, "unexpected length of bytes returned");

	if (memcmp(str, uv[0].v.b.bytes, strlen(str)) != 0)
		return ERR(0, "bytes mismatch");

	/* Try again but with zero space */
	pv[0].type = MDR_RSVB;
	pv[0].v.rsvb.dst = &dst;
	pv[0].v.rsvb.sz = 0;
	if (pmdr_pack(&pm, msg_test_2, pv, 1) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm),
	    MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if ((r = umdr_unpack(&um, msg_test_2, uv, 1)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");
	if (uv[0].v.b.sz != 0)
		return ERR(0, "reserved zero bytes space appears to be "
		    "non-zero");

	return success();
}

static struct test_status *
test_long_tail_bytes()
{
	uint64_t         r, tbsz;
	char             buf[4096];
	char             stra[1024];
	char             strb[128];
	void            *dst, *tb;
	char             strab_expected[2048], strab[2048];
	int              i, j;
	struct pmdr      pm;
	struct pmdr_vec  pv[1];
	struct umdr      um;
	struct umdr_vec  uv[1];

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

	pmdr_init(&pm, buf, sizeof(buf), MDR_FTAILBYTES);
	if (pmdr_pack(&pm, mdr_msg_ping, pv, 0) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	/*
	 * Make space for tail bytes after the MDR payload,
	 * twice for each of our strings
	 */
	if ((r = pmdr_add_tail_bytes(&pm, strlen(stra))) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes stra");
	if ((r = pmdr_add_tail_bytes(&pm, strlen(strb))) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes strb");

	/* Fill the reserved space with our strings */
	pmdr_tail_bytes(&pm, &dst);
	memcpy(dst, stra, strlen(stra));
	memcpy((char *)dst + strlen(stra), strb, strlen(strb));

	/* Test decoding when we disallow tail bytes */
	r = umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE);
	if (r != MDR_FAIL || errno != ENOTSUP)
		return ERR(0, "mdr_unpack_hdr should have failed with ENOTSUP");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FTAILBYTES)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, mdr_msg_ping, uv, 0) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	/* Copy all tail bytes after payload into strab */
	bzero(strab, sizeof(strab));
	tbsz = umdr_tail_bytes(&um, &tb);
	memcpy(strab, tb, tbsz);

	/* Then compare */
	if (memcmp(strab, strab_expected, tbsz) != 0)
		return ERR(0, "bytes don't match");

	return success();
}

static struct test_status *
test_null_bytes()
{
	struct pmdr     pm;
	struct pmdr_vec pv[1];
	struct umdr     um;
	struct umdr_vec uv[1];

	if (pmdr_init(&pm, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = NULL;
	pv[0].v.b.sz = 0;
	if (pmdr_pack(&pm, msg_test_5, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (pmdr_size(&pm) != 21)
		return ERR(0, "mdr with a 0-length bytes field should "
		    "be sized at 21 bytes");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_5, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");
	if (uv[0].v.b.sz != 0)
		return ERR(0, "mdr with a 0-length bytes field should "
		    "have zero length on unpack");
	if (uv[0].v.b.bytes != NULL)
		return ERR(0, "mdr with a 0-length bytes field should "
		    "have NULL value on unpack");
	pmdr_free(&pm);

	if (pmdr_init(&pm, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_S;
	pv[0].v.s = "";
	if (pmdr_pack(&pm, msg_test_0, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (pmdr_size(&pm) != 22)
		return ERR(0, "mdr with a 0-length string field should "
		    "be sized at 22 bytes (length, and \\0)");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_0, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");
	if (uv[0].v.s.sz != 0)
		return ERR(0, "mdr with a 0-length string field should "
		    "have a length of 0 on unpack, for the nul byte");
	if (uv[0].v.s.bytes == NULL || *uv[0].v.s.bytes != '\0')
		return ERR(0, "mdr with a 0-length string field should "
		    "have an empty string on unpack");
	pmdr_free(&pm);

	return success();
}

static struct test_status *
test_limits()
{
	uint64_t        n;
	struct pmdr     pm;
	struct pmdr_vec pv[1];
	char            data[1];

	if (pmdr_init(&pm, NULL, 0, MDR_FTAILBYTES) == MDR_FAIL)
		return ERR(errno, "pmdr_init");

	/*
	 * We cause an overflow by trying to store an amount of data
	 * which is max MDR size minus header and bytes length, +1.
	 * In other words:
	 *   mdr_header + bytes_count (uint64_t) + everything else, +1.
	 */
	n = (PTRDIFF_MAX -
	    (mdr_hdr_size(pmdr_features(&pm)) + sizeof(uint64_t))) + 1;

	pv[0].type = MDR_B;
	pv[0].v.b.bytes = data;
	pv[0].v.b.sz = n;
	if (pmdr_pack(&pm, msg_test_5, pv, PMDRVECLEN(pv)) != MDR_FAIL)
		return ERR(0, "pmdr_pack: expected EOVERFLOW, "
		    "but it succeeded");
	if (errno != EOVERFLOW)
		return ERR(errno,
		    "pmdr_pack: expected EOVERFLOW, got %d\n", errno);

	/*
	 * Here we should be getting ENOMEM because, well, we just
	 * don't have INT64_MAX memory, turns out.
	 * We basically try to store the maximum sized MDR in a buffer.
	 */
	n = PTRDIFF_MAX -
	    (mdr_hdr_size(pmdr_features(&pm)) + sizeof(uint64_t) + 1);
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = data;
	pv[0].v.b.sz = n;
	if (pmdr_pack(&pm, msg_test_5, pv, PMDRVECLEN(pv)) != MDR_FAIL)
		return ERR(0, "pmdr_pack: expected ENOMEM, "
		    "but it succeeded");
	if (errno != ENOMEM)
		return ERR(0, "pmdr_pack: expected ENOMEM, "
		    "got %d\n", errno);

	/*
	 * We should first pack a message successfully before adding
	 * tail bytes.
	 */
	if (pmdr_add_tail_bytes(&pm, UINT64_MAX) != MDR_FAIL)
		return ERR(0, "pmdr_pack: expected EAGAIN, "
		    "but it succeeded");
	if (errno != EAGAIN)
		return ERR(errno,
		    "mdr_add_tail_bytes: expected EAGAIN, got %d\n", errno);

	pv[0].type = MDR_B;
	pv[0].v.b.bytes = data;
	pv[0].v.b.sz = 1;
	if (pmdr_pack(&pm, msg_test_5, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(0, "pmdr_pack");
	if (pmdr_add_tail_bytes(&pm, UINT64_MAX) == MDR_FAIL)
		return ERR(errno, "mdr_add_tail_bytes");
	if (pmdr_add_tail_bytes(&pm, 1) != MDR_FAIL)
		return ERR(0, "mdr_add_tail_bytes: expected EOVERFLOW, "
		    "but it succeeded");
	if (errno != EOVERFLOW)
		return ERR(0, "mdr_add_tail_bytes: expected EOVERFLOW, "
		    "got %d\n", errno);

	pmdr_free(&pm);

	return success();
}

static struct test_status *
test_pack_array()
{
	uint32_t         a_u32[3] = { 0, 1, 2 };
	uint32_t         a_u32_out[3] = { 0, 0, 0 };

	const char      *a_s[] = { "string1", "string2", NULL };
	const char      *a_s_out[3] = { "", "", "" };

	char             buf[1024];
	struct pmdr      pm;
	struct pmdr_vec  pv[2];
	struct umdr      um;
	struct umdr_vec  uv[2];

	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_AU32;
	pv[0].v.au32.items = a_u32;
	pv[0].v.au32.length = 3;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = a_s;
	pv[1].v.as.length = -1;
	if (pmdr_pack(&pm, msg_test_3, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_3, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	if (uv[0].type != MDR_AU32)
		return ERR(0, "first field is not MDR_AU32 as expected");
	if (uv[0].v.au32.length != 3)
		return ERR(0, "first array does not contain 3 items");

	if (umdr_vec_au32(&uv[0].v.au32, a_u32_out, 3) == MDR_FAIL)
		return ERR(errno, "umdr_vec_au32");

	if (memcmp(a_u32, a_u32_out, sizeof(a_u32)) != 0)
		return ERR(0, "first array has wrong content");

	if (uv[1].type != MDR_AS)
		return ERR(0, "second field is not MDR_AS as expected");

	if (umdr_vec_as(&uv[1].v.as, a_s_out, 3) == MDR_FAIL)
		return ERR(errno, "mdr_vec_as");

	if (strcmp(a_s[0], a_s_out[0]) != 0)
		return ERR(0, "a_s_out[0] has wrong content");
	if (strcmp(a_s[1], a_s_out[1]) != 0)
		return ERR(0, "a_s_out[1] has wrong content");
	if (a_s_out[2] != NULL)
		return ERR(0, "a_s_out[2] should be NULL");

	/*
	 * A trailing empty array must still round-trip. The array header
	 * (count, and the byte-size for string/mdr arrays) has to make it
	 * into the message size; otherwise the receiver reads past the end
	 * and unpacking fails with EAGAIN.
	 */
	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_AU32;
	pv[0].v.au32.items = a_u32;
	pv[0].v.au32.length = 3;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = NULL;
	pv[1].v.as.length = 0;
	if (pmdr_pack(&pm, msg_test_3, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack/empty trailing array");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init/empty trailing array");
	if (umdr_unpack(&um, msg_test_3, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack/empty trailing array");

	if (uv[0].v.au32.length != 3)
		return ERR(0, "leading array lost items after empty trailer");
	if (uv[1].v.as.length != 0)
		return ERR(0, "trailing array should be empty");

	/*
	 * Same again with the leading numeric array also empty, so an empty
	 * array in a non-trailing position is exercised too.
	 */
	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_AU32;
	pv[0].v.au32.items = NULL;
	pv[0].v.au32.length = 0;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = NULL;
	pv[1].v.as.length = 0;
	if (pmdr_pack(&pm, msg_test_3, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack/all empty arrays");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init/all empty arrays");
	if (umdr_unpack(&um, msg_test_3, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack/all empty arrays");

	if (uv[0].v.au32.length != 0)
		return ERR(0, "leading array should be empty");
	if (uv[1].v.as.length != 0)
		return ERR(0, "trailing array should be empty");

	return success();
}

static struct test_status *
test_pack_rseq()
{
	struct pmdr_vec    seq[3 * 2], seq2[2 * 2];
	struct umdr_vec    useq[3 * 2], useq2[2 * 2];
	const char         encoded[] =
	    "\x00\x00\x00\x00\x00\x00\x00\x5c" /* size */
	    "\x00\x00\x00\x00"                 /* flags */
	    "\x00\x00\x00\x00"                 /* domain */
	    "\x00\x04"                         /* code */
	    "\x00\x06"                         /* variant */
	    "\x06"                             /* rseq length */
	    "\x00\x00\x00\x00\x00\x00\x00\x18" /* rseq sz */
	    "\x01"                             /* u8 */
	    "\x06\x62\x6c\x61\x68\x31\x00"     /* s blah1 */
	    "\x02"                             /* u8 */
	    "\x06\x62\x6c\x61\x68\x32\x00"     /* s blah2 */
	    "\x03"                             /* u8 */
	    "\x06\x62\x6c\x61\x68\x33\x00"     /* s blah3 */
	    "\x04"                             /* rseq length */
	    "\x00\x00\x00\x00\x00\x00\x00\x1e" /* rseq sz */
	    "\xff\xf6"                         /* i16 */
	    "\x03"                             /* au32 len 3 */
	    "\x00\x00\x00\x00"                 /* u32 */
	    "\x00\x00\x00\x01"                 /* u32 */
	    "\x00\x00\x00\x02"                 /* u32 */
	    "\xff\xf5"                         /* i16 */
	    "\x03"                             /* au32 len 3 */
	    "\x00\x00\x00\x00"                 /* u32 */
	    "\x00\x00\x00\x01"                 /* u32 */
	    "\x00\x00\x00\x02"                 /* u32 */
	    ;
	size_t             encoded_length = sizeof(encoded) - 1;
	uint32_t           au32[3] = { 0, 1, 2 };
	uint32_t           au32_out[3] = { 0, 0, 0 };

	char             buf[1024];
	struct pmdr      pm;
	struct pmdr_vec  pv[2];
	struct umdr      um;
	struct umdr_vec  uv[2];

	seq[MDR_RSEQ_IDX(2, 0, 0)].type = MDR_U8;
	seq[MDR_RSEQ_IDX(2, 0, 0)].v.u8 = 1;
	seq[MDR_RSEQ_IDX(2, 0, 1)].type = MDR_S;
	seq[MDR_RSEQ_IDX(2, 0, 1)].v.s = "blah1";

	seq[MDR_RSEQ_IDX(2, 1, 0)].type = MDR_U8;
	seq[MDR_RSEQ_IDX(2, 1, 0)].v.u8 = 2;
	seq[MDR_RSEQ_IDX(2, 1, 1)].type = MDR_S;
	seq[MDR_RSEQ_IDX(2, 1, 1)].v.s = "blah2";

	seq[MDR_RSEQ_IDX(2, 2, 0)].type = MDR_U8;
	seq[MDR_RSEQ_IDX(2, 2, 0)].v.u8 = 3;
	seq[MDR_RSEQ_IDX(2, 2, 1)].type = MDR_S;
	seq[MDR_RSEQ_IDX(2, 2, 1)].v.s = "blah3";

	seq2[MDR_RSEQ_IDX(2, 0, 0)].type = MDR_I16;
	seq2[MDR_RSEQ_IDX(2, 0, 0)].v.i16 = -10;
	seq2[MDR_RSEQ_IDX(2, 0, 1)].type = MDR_AU32;
	seq2[MDR_RSEQ_IDX(2, 0, 1)].v.au32.items = au32;
	seq2[MDR_RSEQ_IDX(2, 0, 1)].v.au32.length = 3;

	seq2[MDR_RSEQ_IDX(2, 1, 0)].type = MDR_I16;
	seq2[MDR_RSEQ_IDX(2, 1, 0)].v.i16 = -11;
	seq2[MDR_RSEQ_IDX(2, 1, 1)].type = MDR_AU32;
	seq2[MDR_RSEQ_IDX(2, 1, 1)].v.au32.items = au32;
	seq2[MDR_RSEQ_IDX(2, 1, 1)].v.au32.length = 3;

	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_RSEQ;
	pv[0].v.rseq.items = (const struct pmdr_vec *)seq;
	pv[0].v.rseq.length = PMDRVECLEN(seq);
	pv[1].type = MDR_RSEQ;
	pv[1].v.rseq.items = (const struct pmdr_vec *)seq2;
	pv[1].v.rseq.length = PMDRVECLEN(seq2);
	if (pmdr_pack(&pm, msg_test_6, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (memcmp(pmdr_buf(&pm), encoded, encoded_length) != 0)
		return ERR(0, "encoding mismatch");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_6, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	if (umdr_size(&um) != encoded_length)
		return ERR(0, "encoded length should be %zu but was %" PRIu64,
		    encoded_length, umdr_size(&um));

	if (umdr_rseq(&uv[0].v.rseq, useq, UMDRVECLEN(useq)) == MDR_FAIL)
		return ERR(errno, "umdr_rseq");
	if (umdr_rseq(&uv[1].v.rseq, useq2, UMDRVECLEN(useq2)) == MDR_FAIL)
		return ERR(errno, "umdr_rseq");

	if (useq[MDR_RSEQ_IDX(2, 0, 0)].v.u8 != 1 ||
	    useq[MDR_RSEQ_IDX(2, 1, 0)].v.u8 != 2 ||
	    useq[MDR_RSEQ_IDX(2, 2, 0)].v.u8 != 3 ||
	    strcmp(useq[MDR_RSEQ_IDX(2, 0, 1)].v.s.bytes, "blah1") != 0 ||
	    strcmp(useq[MDR_RSEQ_IDX(2, 1, 1)].v.s.bytes, "blah2") != 0 ||
	    strcmp(useq[MDR_RSEQ_IDX(2, 2, 1)].v.s.bytes, "blah3") != 0 ||
	    useq[MDR_RSEQ_IDX(2, 0, 1)].v.s.sz != 5 ||
	    useq[MDR_RSEQ_IDX(2, 1, 1)].v.s.sz != 5 ||
	    useq[MDR_RSEQ_IDX(2, 1, 1)].v.s.sz != 5)
		return ERR(0, "rseq contains wrong values");

	if (useq2[MDR_RSEQ_IDX(2, 0, 0)].v.i16 != -10 ||
	    useq2[MDR_RSEQ_IDX(2, 1, 0)].v.i16 != -11)
		return ERR(0, "rseq contains wrong values");

	if (umdr_vec_au32(&useq2[MDR_RSEQ_IDX(2, 0, 1)].v.au32, au32_out, 3)
	    == MDR_FAIL)
		return ERR(errno, "umdr_vec_au32");

	if (memcmp(au32, au32_out, sizeof(au32)) != 0)
		return ERR(0, "first array has wrong content");

	if (umdr_vec_au32(&useq2[MDR_RSEQ_IDX(2, 1, 1)].v.au32, au32_out, 3)
	    == MDR_FAIL)
		return ERR(errno, "umdr_vec_au32");

	if (memcmp(au32, au32_out, sizeof(au32)) != 0)
		return ERR(0, "second array has wrong content");

	return success();
}

/*
 * Round-trips a repeated sequence that uses every packable element type:
 * all scalar widths, a byte blob, and a spread of array kinds. Two
 * repetitions, so the per-row template is walked more than once. Unlike
 * test_pack_rseq this does not compare against a hand-encoded golden
 * buffer; it relies on pack/unpack agreeing on the wire format.
 */
static struct test_status *
test_pack_rseq_types()
{
	enum { ROWS = 2, COLS = 12 };

	struct pmdr_vec  seq[COLS * ROWS];
	struct umdr_vec  useq[COLS * ROWS];
	uint8_t          au8[ROWS][3]  = { { 10, 11, 12 }, { 20, 21, 22 } };
	int16_t          ai16[ROWS][3] = { { -1, -2, -3 }, { -4, -5, -6 } };
	double           af64[ROWS][2] = { { 1.5, 2.5 }, { 3.5, 4.5 } };
	uint8_t          blob[ROWS][4] = {
		{ 0xde, 0xad, 0xbe, 0xef },
		{ 0x01, 0x02, 0x03, 0x04 }
	};
	const char      *as[ROWS][2] = {
		{ "red", "green" },
		{ "blue", "cyan" }
	};

	uint8_t          au8_out[3];
	int16_t          ai16_out[3];
	double           af64_out[2];
	const char      *as_out[2];

	char             buf[1024];
	struct pmdr      pm;
	struct pmdr_vec  pv[1];
	struct umdr      um;
	struct umdr_vec  uv[1];
	int              r;

	/* The whole sequence collapses to a single vector slot. */
	if (mdr_spec_vlen(msg_test_7) != 1)
		return ERR(0, "spec_vlen should count the rseq block as one");

	for (r = 0; r < ROWS; r++) {
		seq[MDR_RSEQ_IDX(COLS, r, 0)].type  = MDR_U32;
		seq[MDR_RSEQ_IDX(COLS, r, 0)].v.u32 = 0xcafe0000 + r;
		seq[MDR_RSEQ_IDX(COLS, r, 1)].type  = MDR_U64;
		seq[MDR_RSEQ_IDX(COLS, r, 1)].v.u64 = 0x1122334455660000ULL + r;
		seq[MDR_RSEQ_IDX(COLS, r, 2)].type  = MDR_I8;
		seq[MDR_RSEQ_IDX(COLS, r, 2)].v.i8  = -8 - r;
		seq[MDR_RSEQ_IDX(COLS, r, 3)].type  = MDR_I32;
		seq[MDR_RSEQ_IDX(COLS, r, 3)].v.i32 = -123456 - r;
		seq[MDR_RSEQ_IDX(COLS, r, 4)].type  = MDR_I64;
		seq[MDR_RSEQ_IDX(COLS, r, 4)].v.i64 = -9876543210LL - r;
		seq[MDR_RSEQ_IDX(COLS, r, 5)].type  = MDR_F32;
		seq[MDR_RSEQ_IDX(COLS, r, 5)].v.f32 = 1.25f + r;
		seq[MDR_RSEQ_IDX(COLS, r, 6)].type  = MDR_F64;
		seq[MDR_RSEQ_IDX(COLS, r, 6)].v.f64 = 3.0625 + r;

		seq[MDR_RSEQ_IDX(COLS, r, 7)].type    = MDR_B;
		seq[MDR_RSEQ_IDX(COLS, r, 7)].v.b.bytes = blob[r];
		seq[MDR_RSEQ_IDX(COLS, r, 7)].v.b.sz  = sizeof(blob[r]);

		seq[MDR_RSEQ_IDX(COLS, r, 8)].type        = MDR_AU8;
		seq[MDR_RSEQ_IDX(COLS, r, 8)].v.au8.items  = au8[r];
		seq[MDR_RSEQ_IDX(COLS, r, 8)].v.au8.length = 3;
		seq[MDR_RSEQ_IDX(COLS, r, 9)].type         = MDR_AI16;
		seq[MDR_RSEQ_IDX(COLS, r, 9)].v.ai16.items  = ai16[r];
		seq[MDR_RSEQ_IDX(COLS, r, 9)].v.ai16.length = 3;
		seq[MDR_RSEQ_IDX(COLS, r, 10)].type         = MDR_AF64;
		seq[MDR_RSEQ_IDX(COLS, r, 10)].v.af64.items  = af64[r];
		seq[MDR_RSEQ_IDX(COLS, r, 10)].v.af64.length = 2;
		seq[MDR_RSEQ_IDX(COLS, r, 11)].type          = MDR_AS;
		seq[MDR_RSEQ_IDX(COLS, r, 11)].v.as.items  = as[r];
		seq[MDR_RSEQ_IDX(COLS, r, 11)].v.as.length = 2;
	}

	if (pmdr_init(&pm, buf, sizeof(buf), MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_RSEQ;
	pv[0].v.rseq.items = (const struct pmdr_vec *)seq;
	pv[0].v.rseq.length = PMDRVECLEN(seq);
	if (pmdr_pack(&pm, msg_test_7, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "pmdr_pack");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_7, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	if (umdr_rseq(&uv[0].v.rseq, useq, UMDRVECLEN(useq)) != COLS * ROWS)
		return ERR(errno, "umdr_rseq");

	for (r = 0; r < ROWS; r++) {
		struct umdr_vec *row = &useq[MDR_RSEQ_IDX(COLS, r, 0)];

		if (row[0].type != MDR_U32 || row[0].v.u32 != 0xcafe0000 + r)
			return ERR(0, "row %d u32 mismatch", r);
		if (row[1].type != MDR_U64 ||
		    row[1].v.u64 != 0x1122334455660000ULL + r)
			return ERR(0, "row %d u64 mismatch", r);
		if (row[2].type != MDR_I8 || row[2].v.i8 != -8 - r)
			return ERR(0, "row %d i8 mismatch", r);
		if (row[3].type != MDR_I32 || row[3].v.i32 != -123456 - r)
			return ERR(0, "row %d i32 mismatch", r);
		if (row[4].type != MDR_I64 || row[4].v.i64 != -9876543210LL - r)
			return ERR(0, "row %d i64 mismatch", r);
		if (row[5].type != MDR_F32 || row[5].v.f32 != 1.25f + r)
			return ERR(0, "row %d f32 mismatch", r);
		if (row[6].type != MDR_F64 || row[6].v.f64 != 3.0625 + r)
			return ERR(0, "row %d f64 mismatch", r);

		if (row[7].type != MDR_B ||
		    row[7].v.b.sz != sizeof(blob[r]) ||
		    memcmp(row[7].v.b.bytes, blob[r], sizeof(blob[r])) != 0)
			return ERR(0, "row %d blob mismatch", r);

		if (umdr_vec_au8(&row[8].v.au8, au8_out, 3) != 3 ||
		    memcmp(au8_out, au8[r], sizeof(au8[r])) != 0)
			return ERR(0, "row %d au8 mismatch", r);
		if (umdr_vec_ai16(&row[9].v.ai16, ai16_out, 3) != 3 ||
		    memcmp(ai16_out, ai16[r], sizeof(ai16[r])) != 0)
			return ERR(0, "row %d ai16 mismatch", r);
		if (umdr_vec_af64(&row[10].v.af64, af64_out, 2) != 2 ||
		    memcmp(af64_out, af64[r], sizeof(af64[r])) != 0)
			return ERR(0, "row %d af64 mismatch", r);
		if (umdr_vec_as(&row[11].v.as, as_out, 2) != 2 ||
		    strcmp(as_out[0], as[r][0]) != 0 ||
		    strcmp(as_out[1], as[r][1]) != 0)
			return ERR(0, "row %d as mismatch", r);
	}

	pmdr_free(&pm);

	return success();
}

static struct test_status *
test_mdr_spec_base_sz()
{
	size_t sz = mdr_spec_base_sz(msg_test_4, 0);

	if (sz != 115)
		return ERR(0, "sz should be 115 but was %zu", sz);

	sz = mdr_spec_base_sz(mdr_msg_mdrd_bein, 0);
	if (sz != 150)
		return ERR(0, "sz should be 150 but was %zu", sz);

	sz = mdr_hdr_size(MDR_FALL);
	if (sz != 60)
		return ERR(0, "sz should be 60 but was %zu", sz);

	return success();
}

static struct test_status *
test_encoding()
{
	struct pmdr      pm;
	struct pmdr_vec  pv[9];
	struct umdr      um;
	struct umdr_vec  uv[9];
	char            *longstr = "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg"
	    "gggggggggggggggggggggggggggggggg";
	uint8_t          longarray[128];
	uint8_t          longarray_out[128];
	uint64_t         longarray_sz = sizeof(longarray) / sizeof(uint8_t);
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
	size_t           encoded_length = sizeof(encoded) - 1;

	// TODO: test value overflow/boundaries

	bzero(longarray, sizeof(longarray));
	if (pmdr_init(&pm, NULL, 0, MDR_FNONE) == MDR_FAIL)
		return ERR(errno, "pmdr_init");
	pv[0].type = MDR_U64;
	pv[0].v.u64 = 111;
	pv[1].type = MDR_I8;
	pv[1].v.u64 = -128;
	pv[2].type = MDR_U16;
	pv[2].v.u16 = 111;
	pv[3].type = MDR_B;
	pv[3].v.b.bytes = "allo";
	pv[3].v.b.sz = 4;
	pv[4].type = MDR_S;
	pv[4].v.s = "string";
	pv[5].type = MDR_F32;
	pv[5].v.f32 = -111.111;
	pv[6].type = MDR_F64;
	pv[6].v.f64 = -11111.11111;
	pv[7].type = MDR_S;
	pv[7].v.s = longstr;
	pv[8].type = MDR_AU8;
	pv[8].v.au8.length = longarray_sz;
	pv[8].v.au8.items = longarray;
	if (pmdr_pack(&pm, msg_test_4, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		return ERR(errno, "mdr_pack");

	if (pmdr_size(&pm) != encoded_length)
		return ERR(0, "encoded length should be %zu but was %" PRIu64,
		    encoded_length, pmdr_size(&pm));

	if (memcmp(pmdr_buf(&pm), encoded, encoded_length) != 0)
		return ERR(0, "encoding mismatch");

	if (umdr_init(&um, pmdr_buf(&pm), pmdr_size(&pm), MDR_FNONE)
	    == MDR_FAIL)
		return ERR(errno, "umdr_init");
	if (umdr_unpack(&um, msg_test_4, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return ERR(errno, "umdr_unpack");

	if (umdr_size(&um) != encoded_length)
		return ERR(0, "encoded length should be %zu but was %" PRIu64,
		    encoded_length, umdr_size(&um));

	if (uv[0].v.u64 != 111)
		return ERR(0, "decoded u64 is not the right value");
	if (uv[1].v.i8 != -128)
		return ERR(0, "decoded i8 is not the right value");
	if (uv[2].v.u16 != 111)
		return ERR(0, "decoded u16 is not the right value");

	if (uv[3].v.b.sz != strlen("allo"))
		return ERR(0, "decoded bytes size mismatch");
	if (memcmp(uv[3].v.b.bytes, "allo", uv[3].v.b.sz) != 0)
		return ERR(0, "decoded bytes content mismatch");

	if (strcmp(uv[4].v.s.bytes, "string") != 0)
		return ERR(0, "decoded string is not the right value");

	/*
	 * Equality tests on floats are technically a bug but those have
	 * been shown to match
	 */
	if (uv[5].v.f32 != -111.111f)
		return ERR(0, "decoded f32 is not the right value; "
		    "expected=%f, got=%f", -111.111, uv[5].v.f32);
	if (uv[6].v.f64 != -11111.11111)
		return ERR(0, "decoded f64 is not the right value; "
		    "expected=%f, got=%f", -11111.11111, uv[6].v.f64);

	if (strcmp(uv[7].v.s.bytes, longstr) != 0)
		return ERR(0, "decoded long string mismatch");

	if (umdr_vec_alen(&uv[8].v.au8) != longarray_sz)
		return ERR(0, "decoded longarray size mismatch");
	if (umdr_vec_au8(&uv[8].v.au8, longarray_out, 128) == MDR_FAIL)
		return ERR(0, "failed to read longarray");
	if (memcmp(longarray, longarray_out, longarray_sz) != 0)
		return ERR(0, "decoded longarray content mismatch");
	pmdr_free(&pm);

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
		"spec_base_sz",
		1,
		&test_mdr_spec_base_sz
	},
	{
		"pack long strings",
		1,
		&test_long_str
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
		"null bytes",
		1,
		&test_null_bytes
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
	},
	{
		"pack rseq",
		1,
		&test_pack_rseq
	},
	{
		"pack rseq types",
		1,
		&test_pack_rseq_types
	},
	{
		"",
		1,
		NULL
	}
};

static void
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
	if ((msg_test_6 = mdr_register_spec(&msgdef_test_6)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_test_7 = mdr_register_spec(&msgdef_test_7)) == NULL)
		err(1, "mdr_register_spec");

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
	mdr_registry_clear();
	return status;
}
