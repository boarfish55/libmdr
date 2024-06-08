#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "mdr.h"

const char *program = "mdrc";

int debug = 0;
int insecure = 0;

void
usage()
{
	printf("%s: [-dhi] [-t <tls target>] "
	    "<send namespace:id:version> <format> <args>\n",
	    program);
}

void
pack(struct mdr *m, const char *spec, const char **args, int count)
{
	int             finish = 0;
	const char     *p, *prev;
	char           *end;
	char            bytes[1024];
	const char     *bytes_p;
	const char    **a;
	char            b;
	uint64_t        bits;
	uint64_t        u64;
	int64_t         i64;
	int             i;

	/*
	 * A uint64 can render up to 20 digits, plus one for the 'b'
	 * prefix and the terminating NUL byte.
	 */
	char        spbuf[22];

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   b, s
	 */
	for (p = spec, prev = spec, a = args; !finish; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (strlcpy(spbuf, prev,
		    (((p - prev) + 1) < sizeof(spbuf))
		    ? ((p - prev) + 1)
		    : sizeof(spbuf)) >= sizeof(spbuf))
			errx(1, "invalid format spec");

		if (strcmp(spbuf, "b") == 0) {
			for (i = 0, bytes_p = *a++;
			    *bytes_p != '\0' && i < sizeof(bytes); i++) {
				if (*bytes_p++ != 'x')
					errx(1, "invalid value");

				b = tolower(*bytes_p++);
				if (!((b >= '0' && b <= '9') ||
				    (b >= 'a' && b <= 'f')))
					errx(1, "invalid value");

				if (b >= '0' && b <= '9')
					bytes[i] = (b - '0') << 4;
				else
					bytes[i] = (b - 'a' + 10) << 4;

				b = tolower(*bytes_p++);
				if (!((b >= '0' && b <= '9') ||
				    (b >= 'a' && b <= 'f')))
					errx(1, "invalid value");

				if (b >= '0' && b <= '9')
					bytes[i] |= (b - '0');
				else
					bytes[i] |= (b - 'a' + 10);
			}
			if (mdr_pack_bytes(m, bytes, i) == MDR_FAIL)
				err(1, "mdr_pack_bytes");
		} else if (strcmp(spbuf, "s") == 0) {
			if (mdr_pack_string(m, *a++) == MDR_FAIL)
				err(1, "mdr_pack_string");
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2)
				errx(1, "invalid format spec");

			if ((bits = strtoull(spbuf + 1, &end, 10))
			    == ULLONG_MAX || *end != '\0')
				errx(1, "invalid format spec");

			if (spbuf[0] == 'i') {
				i64 = strtoll(*a, &end, 10);
				if (i64 == LLONG_MAX ||
				    i64 == LLONG_MIN || *end != '\0')
					err(1, "invalid value");
			} else {
				u64 = strtoull(*a, &end, 10);
				if (u64 == ULLONG_MAX || *end != '\0')
					err(1, "invalid value");
			}

			switch (bits) {
			case 8:
				if (spbuf[0] == 'i') {
					if (i64 > INT8_MAX || i64 < INT8_MIN)
						errx(1, "invalid value");
					if (mdr_pack_int8(m, i64) == MDR_FAIL)
						err(1, "mdr_pack_uint8");
				} else {
					if (u64 > UINT8_MAX)
						errx(1, "invalid value");
					if (mdr_pack_uint8(m, u64) == MDR_FAIL)
						err(1, "mdr_pack_uint8");
				}
				a++;
				break;
			case 16:
				if (spbuf[0] == 'i') {
					if (i64 > INT16_MAX || i64 < INT16_MIN)
						errx(1, "invalid value");
					if (mdr_pack_int16(m, i64) == MDR_FAIL)
						err(1, "mdr_pack_uint16");
				} else {
					if (u64 > UINT16_MAX)
						errx(1, "invalid value");
					if (mdr_pack_uint16(m, u64) == MDR_FAIL)
						err(1, "mdr_pack_uint16");
				}
				a++;
				break;
			case 32:
				if (spbuf[0] == 'i') {
					if (i64 > INT32_MAX || i64 < INT32_MIN)
						errx(1, "invalid value");
					if (mdr_pack_int32(m, i64) == MDR_FAIL)
						err(1, "mdr_pack_uint32");
				} else {
					if (u64 > UINT32_MAX)
						errx(1, "invalid value");
					if (mdr_pack_uint32(m, u64) == MDR_FAIL)
						err(1, "mdr_pack_uint32");
				}
				a++;
				break;
			case 64:
				if (spbuf[0] == 'i') {
					if (mdr_pack_uint64(m, i64) == MDR_FAIL)
						err(1, "mdr_pack_uint64");
				} else {
					if (mdr_pack_int64(m, u64) == MDR_FAIL)
						err(1, "mdr_pack_uint64");
				}
				a++;
				break;
			default:
				errx(1, "invalid format spec");
			}
		} else {
			/* Unknown type specifier */
			errx(1, "invalid format spec");
		}
		prev = p + 1;
	}
}

void
ssl_err()
{
	ERR_print_errors_fp(stderr);
	exit(1);
}

void
do_tls(struct mdr *m, const char *target)
{
	SSL_CTX        *ctx;
	BIO            *b;
	SSL            *ssl;
	int             r, len;
	char           *buf;
	size_t          buf_sz;

	if (mdr_size(m) >= INT_MAX)
		errx(1, "payload too large for sending");

	if ((ctx = SSL_CTX_new(TLS_method())) == NULL)
		ssl_err();

	if (insecure)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	else
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	if (!SSL_CTX_set_default_verify_paths(ctx))
		ssl_err();

	if ((b = BIO_new_ssl_connect(ctx)) == NULL)
		ssl_err();

	BIO_get_ssl(b, &ssl);
	if (ssl == NULL)
		ssl_err();

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(b, target);

	if (BIO_do_connect(b) <= 0)
		ssl_err();

	if (BIO_do_handshake(b) <= 0)
		ssl_err();

	if ((r = BIO_write(b, mdr_buf(m), mdr_size(m))) == -1)
		ssl_err();
	else if (r < mdr_size(m))
		errx(1, "short write: %d < %lu", r, mdr_size(m));
	mdr_free(m);

	buf_sz = 4096;
	if ((buf = malloc(buf_sz)) == NULL)
		err(1, "malloc");
	for (len = 0;;) {
		r = BIO_read(b, buf + len, buf_sz - len);
		if (r == -1 && !BIO_should_retry(b))
			ssl_err();
		len += r;
		if (mdr_unpack_hdr(m, buf, len) == MDR_FAIL) {
			if (errno == EAGAIN)
				continue;
			else
				err(1, "mdr_unpack_hdr");
		}
		if (!mdr_pending(m))
			break;
		if (buf_sz >= mdr_size(m))
			continue;
		if (mdr_size(m) >= INT_MAX)
			errx(1, "payload too large for receiving");
		buf = realloc(buf, mdr_size(m));
		if (buf == NULL)
			err(1, "realloc");
		buf_sz = mdr_size(m);
	}
	BIO_free_all(b);
	printf("\nReceived:\n");
	mdr_print(m);
	free(buf);
	SSL_CTX_free(ctx);
}

int
main(int argc, char **argv)
{
	unsigned long  l;
	int            opt;
	uint32_t       namespace = 0;
	uint16_t       id = 0, version = 0;
	char          *msgid, *p;
	char          *format, *spec, *end;
	int            count, r;
	const char    *tls_target = NULL;
	struct mdr     m;

	while ((opt = getopt(argc, argv, "hdit:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'd':
			debug = 1;
			break;
		case 't':
			tls_target = optarg;
			break;
		case 'i':
			insecure = 1;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (optind >= argc) {
		usage();
		exit(1);
	}

	msgid = argv[optind++];

	if ((p = strtok(msgid, ":")) == NULL) {
		usage();
		exit(1);
	}
	if ((l = strtoul(p, &end, 10)) == ULONG_MAX || *end != '\0')
		err(1, "invalid namespace");
	namespace = l;

	if ((p = strtok(NULL, ":")) == NULL) {
		usage();
		exit(1);
	}
	if ((l = strtoul(p, &end, 10)) == ULONG_MAX || *end != '\0')
		err(1, "invalid id");
	if (l > UINT16_MAX)
		errx(1, "id out of range");
	id = l;

	if ((p = strtok(NULL, ":")) == NULL) {
		usage();
		exit(1);
	}
	if ((l = strtoul(p, &end, 10)) == ULONG_MAX || *end != '\0')
		err(1, "invalid version");
	if (l > UINT16_MAX)
		errx(1, "version out of range");
	version = l;

	format = argv[optind++];
	if (strlen(format) < 1) {
		usage();
		exit(1);
	}

	for (count = 1, spec = strchr(format, ':'); spec != NULL; count++)
		spec = strchr(spec + 1, ':');

	if (argc - optind != count) {
		usage();
		exit(1);
	}

	r = mdr_pack_hdr(&m, 0, namespace, id, version, NULL, 0);
	if (r == MDR_FAIL)
		err(1, "mdr_pack_hdr");

	pack(&m, format, (const char **)argv + optind, argc - optind);

	if (tls_target == NULL) {
		mdr_print(&m);
		mdr_free(&m);
		return 0;
	}

	printf("Sent:\n");
	mdr_print(&m);
	do_tls(&m, tls_target);
	return 0;
}
