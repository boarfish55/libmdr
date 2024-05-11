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

	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	r = mdr_encode(&echo, MDR_NS_ECHO, MDR_ID_ECHO, 0, NULL, 0);
	printf("mdr_encode=%lu\n", r);

	r = mdr_pack_string(&echo, str);
	printf("mdr_pack_string=%lu\n", r);

	r = mdr_decode(&decode, mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_decode=%lu\n", r);

	len = sizeof(str2);
	r = mdr_unpack_string(&decode, str2, &len);
	printf("mdr_unpack_string(s)=%.*s (%lu -> %lu)\n",
	    (int)((len < sizeof(str2)) ? len - 1 : sizeof(str2) - 1),
	    str2, len, sizeof(str2));
	mdr_free(&echo);
}

void
test_long_tail_bytes()
{
	uint64_t   r, len;
	struct mdr echo, decode;
	char       buf[4096];
	char       str[1024], str2[1024];
	int        i;

	bzero(str2, sizeof(str2));
	for (i = 0; i < sizeof(str) - 1; i++)
		str[i] = 'a';
	str[i] = '\0';

	r = mdr_encode(&echo, MDR_NS_ECHO, MDR_ID_ECHO, 0, buf, sizeof(buf));
	printf("mdr_encode=%lu\n", r);

	r = mdr_pack_tail_bytes(&echo, sizeof(str));
	printf("mdr_pack_tail_bytes=%lu\n", r);
	memcpy(buf + r, str, sizeof(str));

	r = mdr_decode(&decode, mdr_buf(&echo), mdr_size(&echo));
	printf("mdr_decode=%lu\n", r);

	r = mdr_unpack_tail_bytes(&decode, &len);
	printf("mdr_unpack_tail_bytes() -> %lu -> %lu\n", r, len);
	memcpy(str2, buf + r, len);
	printf("unpacked string: %s -> %lu\n", str2, len);
}

void
test_limits()
{
	uint64_t   r, n;
	struct mdr echo;
	char       str[1];

	r = mdr_encode(&echo, MDR_NS_ECHO, MDR_ID_ECHO, 0, NULL, 0);
	printf("mdr_encode=%lu\n", r);

	n = (PTRDIFF_MAX - (mdr_hdr_size() + 9)) + 1;
	errno = 0;
	r = mdr_pack_bytes(&echo, str, n);
	if (errno != EOVERFLOW)
		printf("mdr_pack_bytes(b): expected EOVERFLOW, got %d\n", errno);

	n = PTRDIFF_MAX - (mdr_hdr_size() + 9 + 1);
	errno = 0;
	r = mdr_pack_bytes(&echo, str, n);
	if (errno != ENOMEM)
		printf("mdr_pack_bytes(b): expected ENOMEM, got %d\n", errno);

	n = UINT64_MAX - (mdr_hdr_size() + 9);
	errno = 0;
	r = mdr_pack_tail_bytes(&echo, n);
	if (errno != EOVERFLOW)
		printf("mdr_pack_bytes(b): expected EOVERFLOW, got %d\n", errno);

	mdr_free(&echo);
}

void
test_echo()
{
	int             i;
	struct mdr_echo e_src, e_dst;
	uint64_t        r;

	bzero(&e_src, sizeof(e_src));
	for (i = 0; i < sizeof(e_src.echo) - 1; i++)
		e_src.echo[i] = 'a';

	printf("mdr_echo_encode=%lu\n", mdr_echo_encode(&e_src));

	bzero(&e_dst, sizeof(e_dst));

	r = mdr_echo_decode(&e_dst, mdr_buf(&e_src.m), mdr_size(&e_src.m));
	printf("mdr_echo_decode=%lu => %s (%ld)\n",
	    r, e_dst.echo, strlen(e_dst.echo));
	mdr_free(&e_src.m);
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

	r = mdr_encode(&echo, MDR_NS_ECHO, MDR_ID_ECHO, 0,
	    buf_echo, sizeof(buf_echo));
	printf("mdr_encode=%lu\n", r);

	r = mdr_pack(&echo, "u64", 111);
	printf("mdr_pack(u64)=%lu\n", r);

	r = mdr_pack(&echo, "i8", 111);
	printf("mdr_pack(i8)=%lu\n", r);

	r = mdr_pack(&echo, "u16", 111);
	printf("mdr_pack(u16)=%lu\n", r);

	r = mdr_pack(&echo, "b", "allo", 4);
	printf("mdr_pack(b4)=%lu\n", r);

	r = mdr_pack(&echo, "s", "string");
	printf("mdr_pack(b4)=%lu\n", r);


	r = mdr_encode(&echo2, MDR_NS_ECHO, MDR_ID_ECHO, 0, buf_echo2,
	    sizeof(buf_echo2));
	printf("mdr_encode=%lu\n", r);

	r = mdr_pack(&echo2, "u64:i8:u16:b:s", 111, 111, 111,
	    "allo", 4, "string");
	printf("mdr_pack(u64)=%lu\n", r);

	printf("memcmp(buf, buf2)==%d\n",
	    memcmp(buf_echo, buf_echo2, mdr_size(&echo2)));


	r = mdr_decode(&decho, buf_echo2, sizeof(buf_echo2));
	printf("mdr_encode=%lu\n", r);
	dlen = sizeof(dbytes);
	dstr_len = sizeof(dstr);
	r = mdr_unpack(&decho, "u64:i8:u16:b:s", &u64, &i8, &u16, 
	    dbytes, &dlen, dstr, &dstr_len);

	printf("u64: 111 == %lu\n", u64);
	printf("i8: 111 == %d\n", i8);
	printf("u16: 111 == %u\n", u16);
	printf("dbytes: allo == [%.*s] (%d)\n", (int)dlen, dbytes, (int)dlen);
	printf("dstr: string == %s\n", dstr);

	r = mdr_encode(&echo3, MDR_NS_ECHO, MDR_ID_ECHO, 0,
	    buf_echo3, sizeof(buf_echo3));
	printf("mdr_encode=%lu\n", r);

	r = mdr_pack_bytes(&echo3, str5, strlen(str5));
	printf("mdr_pack_bytes(b)=%lu\n", r);

	r = mdr_decode(&echo3, buf_echo3, sizeof(buf_echo3));
	printf("mdr_decode=%lu\n", r);

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

	return 0;
}
