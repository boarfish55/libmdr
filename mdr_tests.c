#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdr.h"

void
test_long_str()
{
	int        i;
	uint64_t   r, len;
	char       str[1024], str2[1000];
	struct mdr echo, decode;

	printf("%s\n", __func__);

	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	r = mdr_pack_hdr(&echo, NULL, 0, 0, MDR_NS_ECHO, MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_pack_string(&echo, str);
	printf("mdr_pack_string=%lu\n", r);

	r = mdr_unpack_hdr(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_unpack_hdr=%lu\n", r);

	len = sizeof(str2);
	r = mdr_unpack_string(&decode, str2, &len);
	printf("mdr_unpack_string(s)=%.*s (%lu -> %lu)\n",
	    (int)((len < sizeof(str2)) ? len - 1 : sizeof(str2) - 1),
	    str2, len, sizeof(str2));
	mdr_free(&echo);
}

void
test_pack_mdr()
{
	uint64_t   r, len;
	char       buf[64], buf2[64];
	char       str[32] = "hey hey hey";
	struct mdr echo, echo2, decode;

	printf("%s\n", __func__);

	/* Create inner mdr, containing a string */
	r = mdr_pack_hdr(&echo2, buf2, sizeof(buf2), 0, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);
	r = mdr_pack_string(&echo2, str);
	printf("mdr_pack_string=%lu\n", r);

	r = mdr_pack_hdr(&echo, buf, sizeof(buf), 0, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_pack_mdr(&echo, &echo2);
	printf("mdr_pack_mdr=%lu\n", r);
	printf("mdr_size=%lu\n", mdr_size(&echo));

	r = mdr_unpack_hdr(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_unpack_hdr=%lu\n", r);

	len = sizeof(buf2);
	bzero(buf2, len);
	bzero(&echo2, sizeof(echo2));
	r = mdr_unpack_mdr_ref(&decode, &echo2);
	printf("mdr_unpack_mdr=%lu\n", r);

	bzero(str, sizeof(str));
	len = sizeof(str);
	r = mdr_unpack_string(&echo2, str, &len);
	printf("mdr_unpack_string(s)=%.*s (%lu fits in %lu)\n",
	    (int)((len < sizeof(str)) ? len - 1 : sizeof(str) - 1),
	    str, len, sizeof(str));
}

void
test_pack_space()
{
	uint64_t    r, len;
	char        buf[64];
	char        str[32] = "hey hey hey";
	char       *dst;
	const char *src;
	struct mdr  echo, decode;

	printf("%s\n", __func__);

	/* Create inner mdr, containing a string */
	r = mdr_pack_hdr(&echo, buf, sizeof(buf), 0, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_pack_space(&echo, &dst, strlen(str));
	printf("mdr_pack_space=%lu\n", r);

	memcpy(dst, str, strlen(str));

	r = mdr_unpack_hdr(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_unpack_hdr=%lu\n", r);

	r = mdr_unpack_bytes_ref(&decode, &src, &len);
	printf("mdr_unpack_bytes_ref=%lu => %.*s\n", r, (int)len, src);

	mdr_reset(&decode);
	len = sizeof(str);
	bzero(str, sizeof(str));
	r = mdr_unpack_bytes(&decode, str, &len);
	printf("mdr_unpack_bytes=%lu => %.*s\n", r, (int)len, str);

	r = mdr_pack_hdr(&echo, buf, sizeof(buf), 0, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0);
	r = mdr_pack_space(&echo, &dst, 0);
	printf("mdr_pack_space=%lu\n", r);

	r = mdr_unpack_hdr(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	r = mdr_unpack_bytes(&decode, str, &len);
	printf("mdr_unpack_bytes=%lu => %lu\n", r, len);

	r = mdr_pack(&echo, buf, sizeof(buf), 0, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0, "p", &dst, strlen(str));
	memcpy(dst, str, strlen(str));

	bzero(str, sizeof(str));
	r = mdr_unpack(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo), "p", &str, &len);
	printf("mdr_unpack_bytes_ref=%lu => %.*s\n", r, (int)len, src);
}

void
test_long_tail_bytes()
{
	uint64_t   r;
	struct mdr echo, decode;
	char       buf[4096];
	char       stra[1024], stra2[1024];
	char       strb[128], strb2[128];
	char       strab[2048];
	int        i;

	printf("%s\n", __func__);

	bzero(stra2, sizeof(stra2));
	bzero(strb2, sizeof(strb2));
	for (i = 0; i < sizeof(stra) - 1; i++)
		stra[i] = 'a';
	stra[i] = '\0';
	for (i = 0; i < sizeof(strb) - 1; i++)
		strb[i] = 'b';
	strb[i] = '\0';

	r = mdr_pack_hdr(&echo, buf, sizeof(buf), MDR_F_TAIL_BYTES,
	    MDR_NS_ECHO, MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_add_tail_bytes(&echo, strlen(stra));
	printf("mdr_pack_tail_bytes=%lu\n", r);
	r = mdr_add_tail_bytes(&echo, strlen(strb));
	printf("mdr_pack_tail_bytes=%lu\n", r);

	memcpy(buf + r, stra, strlen(stra));
	memcpy(buf + r + strlen(stra), strb, strlen(strb));

	r = mdr_unpack_hdr(&decode, MDR_F_NONE,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	if (r != MDR_FAIL || errno != EACCES)
		printf("mdr_unpack_hdr should have failed with EACCES");

	r = mdr_unpack_hdr(&decode, MDR_F_TAIL_BYTES,
	    (void *)mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_unpack_hdr=%lu\n", r);

	bzero(strab, sizeof(strab));
	memcpy(strab, buf + r, mdr_tail_bytes(&decode));
	printf("unpacked string: %s -> %lu\n", strab, strlen(strab));
}

void
test_limits()
{
	uint64_t   r, n;
	struct mdr echo;
	char       str[1];

	printf("%s\n", __func__);

	r = mdr_pack_hdr(&echo, NULL, 0, MDR_F_TAIL_BYTES, MDR_NS_ECHO,
	    MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	n = (PTRDIFF_MAX -
	    (mdr_hdr_size(mdr_flags(&echo)) + sizeof(uint64_t))) + 1;
	errno = 0;
	r = mdr_pack_bytes(&echo, str, n);
	if (errno != EOVERFLOW)
		printf("mdr_pack_bytes(b): expected EOVERFLOW, got %d\n",
		    errno);

	n = PTRDIFF_MAX -
	    (mdr_hdr_size(mdr_flags(&echo)) + sizeof(uint64_t) + 1);
	errno = 0;
	r = mdr_pack_bytes(&echo, str, n);
	if (errno != ENOMEM)
		printf("mdr_pack_bytes(b): expected ENOMEM, got %d\n", errno);

	errno = 0;
	n = UINT64_MAX;
	mdr_add_tail_bytes(&echo, n);
	r = mdr_add_tail_bytes(&echo, 1);
	if (errno != EOVERFLOW)
		printf("mdr_add_tail_bytes(b): expected EOVERFLOW, got %d\n",
		    errno);

	mdr_free(&echo);
}

void
test_echo()
{
	int        i;
	struct mdr src, dst;
	char       str[1024];
	size_t     str_sz;
	uint64_t   r;

	printf("%s\n", __func__);

	bzero(str, sizeof(str));
	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';

	printf("mdr_pack_echo=%lu\n", mdr_pack_echo(&src, str));

	bzero(str, sizeof(str));

	str_sz = sizeof(str);
	r = mdr_unpack_echo(&dst, (void *)mdr_buf(&src), mdr_size(&src),
	    str, &str_sz);
	printf("mdr_unpack_echo=%lu => %s (%ld)\n", r, str, str_sz);
	mdr_free(&src);
}

int
main()
{
	char       buf_echo[1024], buf_echo2[1024], buf_echo3[1024];
	char       str5[5] = "allo";
	struct mdr echo, echo2, echo3, decho;
	uint64_t   r, len;
	uint64_t   u64 = 0;
	uint16_t   u16 = 0;
	int8_t     i8 = 0;
	char       dbytes[1024];
	uint64_t   dlen = 0;
	char       dstr[1024];
	uint64_t   dstr_len;

	r = mdr_pack_hdr(&echo, buf_echo, sizeof(buf_echo), 0,
	    MDR_NS_ECHO, MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_packf(&echo, "u64", 111);
	printf("mdr_packf(u64)=%lu\n", r);

	r = mdr_packf(&echo, "i8", -111);
	printf("mdr_packf(i8)=%lu\n", r);

	r = mdr_packf(&echo, "u16", 111);
	printf("mdr_packf(u16)=%lu\n", r);

	r = mdr_packf(&echo, "b", "allo", 4);
	printf("mdr_packf(b4)=%lu\n", r);

	r = mdr_packf(&echo, "s", "string");
	printf("mdr_packf(b4)=%lu\n", r);

	r = mdr_pack_hdr(&echo2, buf_echo2, sizeof(buf_echo2), 0,
	    MDR_NS_ECHO, MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_packf(&echo2, "u64:i8:u16:b:s", 111, -111, 111,
	    "allo", 4, "string");
	printf("mdr_packf(u64)=%lu\n", r);

	printf("memcmp(buf, buf2)==%d\n",
	    memcmp(buf_echo, buf_echo2, mdr_size(&echo2)));

	r = mdr_unpack_hdr(&decho, MDR_F_NONE, buf_echo2, sizeof(buf_echo2));
	printf("mdr_unpack_hdr=%lu\n", r);
	dlen = sizeof(dbytes);
	dstr_len = sizeof(dstr);
	r = mdr_unpackf(&decho, "u64:i8:u16:b:s", &u64, &i8, &u16,
	    dbytes, &dlen, dstr, &dstr_len);

	printf("unpackf:u64: 111 == %lu\n", u64);
	printf("unpackf:i8: -111 == %d\n", i8);
	printf("unpackf:u16: 111 == %u\n", u16);
	printf("unpackf:dbytes: allo == [%.*s] (%d)\n",
	    (int)dlen, dbytes, (int)dlen);
	printf("unpackf:dstr: string == %s\n", dstr);

	r = mdr_pack_hdr(&echo3, buf_echo3, sizeof(buf_echo3), 0,
	    MDR_NS_ECHO, MDR_ID_ECHO, 0);
	printf("mdr_pack_hdr=%lu\n", r);

	r = mdr_pack_bytes(&echo3, str5, strlen(str5));
	printf("mdr_pack_bytes(b)=%lu\n", r);

	r = mdr_unpack_hdr(&echo3, MDR_F_NONE, buf_echo3, sizeof(buf_echo3));
	printf("mdr_unpack_hdr=%lu\n", r);

	len = sizeof(str5);
	r = mdr_unpack_bytes(&echo3, str5, &len);
	printf("mdr_unpack_bytes(b)=%.*s (%lu)\n", (int)len, str5, len);


	printf("mdr_reset()=%d\n", mdr_reset(&echo3));
	len = sizeof(str5);
	r = mdr_unpack_string(&echo3, str5, &len);
	printf("mdr_unpack_string(s)=%.*s (%lu)\n", (int)len, str5, len);

	printf("mdr_reset()=%d\n", mdr_reset(&echo3));
	len = sizeof(buf_echo);
	r = mdr_unpack_string(&echo3, buf_echo, &len);
	printf("mdr_unpack_string(s)=%.*s (%lu)\n", (int)len, buf_echo, len);

	test_long_str();

	test_echo();

	test_long_tail_bytes();

	test_limits();

	printf("\n");
	test_pack_mdr();

	test_pack_space();
	return 0;
}
