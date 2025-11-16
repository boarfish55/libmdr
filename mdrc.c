#include <sys/socket.h>
#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "mdr.h"

const char            *program = "mdrc";
const struct mdr_spec *m_spec;

int debug = 0;
int delay = 0;
int insecure = 0;
int repeat = 1;
int rcvbuf = 0;

void
usage()
{
	printf("%s: [-dhi] [-n <repeat>] [-t <tls target|->] "
	    "[-B <rcvbuf>] "
	    "[-k <key> -c <cert>] "
	    "<send domain:code:varian> <format> <args>\n", program);
}

void
pack(struct pmdr *m, const char *spec, const char **args, int count)
{
	int               finish = 0;
	const char       *p, *prev;
	char             *end;
	char              bytes[1024];
	const char       *bytes_p;
	const char      **a;
	char              b;
	uint64_t          bits;
	uint64_t          u64;
	int64_t           i64;
	float             f32;
	double            f64;
	int               i;
	struct pmdr_vec   pv[count];
	int               pvi = 0;
	struct pmdr       subm[count];
	unsigned char    *subm_bytes[count];

	bzero(subm_bytes, sizeof(subm_bytes));

	/*
	 * A uint64 can render up to 20 digits, plus one for the 'b'
	 * prefix and the terminating NUL byte.
	 */
	char        spbuf[22];

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   bN, sN
	 */
	for (p = spec, prev = spec, a = args;
	    !finish && a - args < count; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (strlcpy(spbuf, prev,
		    (((p - prev) + 1) < sizeof(spbuf))
		    ? ((p - prev) + 1)
		    : sizeof(spbuf)) >= sizeof(spbuf))
			errx(1, "invalid format spec");

		if (strcmp(spbuf, "m") == 0) {
			for (i = 0, bytes_p = *a;
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
			if ((subm_bytes[pvi] = malloc(i)) == NULL)
				err(1, "malloc");
			memcpy(subm_bytes[pvi], bytes, i);
			if (pmdr_init(&subm[pvi], subm_bytes[pvi], i, MDR_FNONE)
			    == MDR_FAIL)
				err(1, "umdr_init");
			pv[pvi].type = MDR_M;
			pv[pvi].v.pmdr = &subm[pvi];
		} else if (strcmp(spbuf, "b") == 0) {
			for (i = 0, bytes_p = *a;
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
			if ((subm_bytes[pvi] = malloc(i)) == NULL)
				err(1, "malloc");
			memcpy(subm_bytes[pvi], bytes, i);
			pv[pvi].type = MDR_B;
			pv[pvi].v.b.bytes = subm_bytes[pvi];
			pv[pvi].v.b.sz = i;
		} else if (strcmp(spbuf, "s") == 0) {
			pv[pvi].type = MDR_S;
			pv[pvi].v.s = *a;
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2)
				errx(1, "invalid format spec");

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (errno || *end != '\0')
				errx(1, "invalid format spec");

			if (spbuf[0] == 'i') {
				errno = 0;
				i64 = strtoll(*a, &end, 10);
				if (errno || *end != '\0')
					err(1, "invalid value");
			} else {
				errno = 0;
				u64 = strtoull(*a, &end, 10);
				if (errno || *end != '\0')
					err(1, "invalid value");
			}

			switch (bits) {
			case 8:
				if (spbuf[0] == 'i') {
					if (i64 > INT8_MAX || i64 < INT8_MIN)
						errx(1, "invalid value");
					pv[pvi].type = MDR_I8;
					pv[pvi].v.i8 = i64;
				} else {
					if (u64 > UINT8_MAX)
						errx(1, "invalid value");
					pv[pvi].type = MDR_U8;
					pv[pvi].v.u8 = u64;
				}
				break;
			case 16:
				if (spbuf[0] == 'i') {
					if (i64 > INT16_MAX || i64 < INT16_MIN)
						errx(1, "invalid value");
					pv[pvi].type = MDR_I16;
					pv[pvi].v.i16 = i64;
				} else {
					if (u64 > UINT16_MAX)
						errx(1, "invalid value");
					pv[pvi].type = MDR_U16;
					pv[pvi].v.u16 = u64;
				}
				break;
			case 32:
				if (spbuf[0] == 'i') {
					if (i64 > INT32_MAX || i64 < INT32_MIN)
						errx(1, "invalid value");
					pv[pvi].type = MDR_I32;
					pv[pvi].v.i32 = i64;
				} else {
					if (u64 > UINT32_MAX)
						errx(1, "invalid value");
					pv[pvi].type = MDR_U32;
					pv[pvi].v.u32 = u64;
				}
				break;
			case 64:
				if (spbuf[0] == 'i') {
					pv[pvi].type = MDR_I64;
					pv[pvi].v.i64 = i64;
				} else {
					pv[pvi].type = MDR_U64;
					pv[pvi].v.u64 = u64;
				}
				break;
			default:
				errx(1, "invalid format spec");
			}
			a++;
		} else if (spbuf[0] == 'f') {
			if (strlen(spbuf) < 3)
				errx(1, "invalid format spec");

			errno = 0;
			bits = strtoull(spbuf + 1, &end, 10);
			if (errno || *end != '\0')
				errx(1, "invalid format spec");

			switch (bits) {
			case 32:
				errno = 0;
				f32 = strtof(*a, &end);
				if (errno || *end != '\0')
					err(1, "invalid value");
				pv[pvi].type = MDR_F32;
				pv[pvi].v.f32 = f32;
				break;
			case 64:
				errno = 0;
				f64 = strtod(*a, &end);
				if (errno || *end != '\0')
					err(1, "invalid value");
				pv[pvi].type = MDR_F64;
				pv[pvi].v.f64 = f64;
				break;
			default:
				errx(1, "invalid format spec");
			}
		} else {
			/* Unknown type specifier */
			errx(1, "invalid format spec");
		}
		a++;
		pvi++;
		prev = p + 1;
	}
	if (pmdr_pack(m, m_spec, pv, count) == MDR_FAIL)
		err(1, "pmdr_pack");
	for (i = 0; i < count; i++)
		if (subm_bytes[i] != NULL)
			free(subm_bytes[i]);
}

void
ssl_err()
{
	fprintf(stderr, "ssl_err:\n");
	ERR_print_errors_fp(stderr);
	exit(1);
}

void
do_tls(struct pmdr *m, const char *target, const char *key_path,
    const char *crt_path)
{
	SSL_CTX         *ctx;
	BIO             *b;
	SSL             *ssl;
	int              i, j, r, len;
	int              fd;
	char            *buf;
	size_t           buf_sz;
	struct umdr      reply;
	struct timespec  delay_ns;

	if (pmdr_size(m) >= INT_MAX)
		errx(1, "payload too large for sending");

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		ssl_err();

	if (insecure)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	else
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	if (!SSL_CTX_set_default_verify_paths(ctx))
		ssl_err();

	if (key_path != NULL && crt_path != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ctx, key_path,
		    SSL_FILETYPE_PEM) != 1)
			ssl_err();
		if (SSL_CTX_use_certificate_file(ctx, crt_path,
		    SSL_FILETYPE_PEM) != 1)
			ssl_err();
	}

	if ((b = BIO_new_ssl_connect(ctx)) == NULL)
		ssl_err();

	BIO_get_ssl(b, &ssl);
	if (ssl == NULL)
		ssl_err();

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(b, target);

	if (BIO_do_connect(b) <= 0)
		ssl_err();

	if (rcvbuf > 0) {
		fd = BIO_get_fd(b, NULL);
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
		    &rcvbuf, sizeof(rcvbuf)) == -1)
			err(1, "setsockopt");
	}

	if (BIO_do_handshake(b) <= 0)
		ssl_err();

	for (i = 0; i < repeat; i++) {
		if (i > 0)
			printf("\n");
		printf("Sent:\n");
		pmdr_print(stdout, m);

		if (delay == 0) {
			if ((r = BIO_write(b, pmdr_buf(m), pmdr_size(m))) == -1)
				ssl_err();
			else if (r < pmdr_size(m))
				errx(1, "short write: %d < %lu", r,
				    pmdr_size(m));
		} else {
			for (j = 0; j < pmdr_size(m); j++) {
				delay_ns.tv_sec = delay / 1000;
				delay_ns.tv_nsec = (delay % 1000) * 1000000;
				if ((r = BIO_write(b, pmdr_buf(m) + j, 1)) == -1)
					ssl_err();
				else if (r < 1)
					errx(1, "short write: %d < 1", r);
				nanosleep(&delay_ns, NULL);
			}
		}

		buf_sz = 4096;
		if ((buf = malloc(buf_sz)) == NULL)
			err(1, "malloc");
		for (len = 0;;) {
			r = BIO_read(b, buf + len, buf_sz - len);
			if (r <= 0 && !BIO_should_retry(b))
				ssl_err();
			len += r;
			/*
			 * We re-init everytime in case our buffer
			 * moved after realloc() below.
			 */
			if (umdr_init(&reply, buf, len, MDR_FNONE)
			    == MDR_FAIL) {
				if (errno == EAGAIN)
					continue;
				else
					err(1, "mdr_init_unpack");
			}
			if (!umdr_pending(&reply))
				break;
			if (buf_sz >= umdr_size(&reply))
				continue;
			if (umdr_size(&reply) >= INT_MAX)
				errx(1, "payload too large for receiving");
			buf_sz = umdr_size(&reply);
			buf = realloc(buf, buf_sz);
			if (buf == NULL)
				err(1, "realloc");
		}
		printf("\nReceived:\n");
		umdr_print(stdout, &reply);
		free(buf);
	}
	pmdr_free(m);
	BIO_free_all(b);
	SSL_CTX_free(ctx);
}

void
do_stdin()
{
	int          r, len;
	char        *buf;
	size_t       buf_sz;
	struct umdr  reply;

	for (;;) {
		buf_sz = 4096;
		if ((buf = malloc(buf_sz)) == NULL)
			err(1, "malloc");
		for (len = 0;;) {
			r = read(0, buf + len, buf_sz - len);
			if (r == -1)
				err(1, "read");

			if (r == 0) {
				free(buf);
				return;
			}

			len += r;
			if (umdr_init(&reply, buf, len, MDR_FNONE)
			    == MDR_FAIL) {
				if (errno == EAGAIN)
					continue;
				else
					err(1, "mdr_init_unpack");
			}
			if (!umdr_pending(&reply))
				break;
			if (buf_sz >= umdr_size(&reply))
				continue;
			if (umdr_size(&reply) >= INT_MAX)
				errx(1, "payload too large for receiving");
			buf = realloc(buf, umdr_size(&reply));
			if (buf == NULL)
				err(1, "realloc");
			buf_sz = umdr_size(&reply);
		}
		printf("\nReceived:\n");
		umdr_print(stdout, &reply);
		free(buf);
	}
}

void
do_stdout(struct pmdr *m)
{
	int i, r;

	if (pmdr_size(m) >= INT_MAX)
		errx(1, "payload too large for sending");

	for (i = 0; i < repeat; i++) {
		if (i > 0)
			printf("\n");
		fprintf(stderr, "Sent:\n");
		pmdr_print(stderr, m);

		if ((r = write(1, pmdr_buf(m), pmdr_size(m))) == -1)
			err(1, "write");
		else if (r < pmdr_size(m))
			errx(1, "short write: %d < %lu", r, pmdr_size(m));
	}
	pmdr_free(m);
}

int
main(int argc, char **argv)
{
	unsigned long  l;
	int            opt;
	uint32_t       domain = 0;
	uint16_t       code = 0, variant = 0;
	char          *msgcode, *p;
	char          *format, *spec, *end;
	int            count, r;
	const char    *target = NULL;
	const char    *key_path = NULL;
	const char    *crt_path = NULL;
	struct pmdr    m;

	while ((opt = getopt(argc, argv, "hdit:k:c:n:D:B:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'd':
			debug = 1;
			break;
		case 'D':
			delay = atoi(optarg);
			break;
		case 't':
			target = optarg;
			break;
		case 'k':
			key_path = optarg;
			break;
		case 'c':
			crt_path = optarg;
			break;
		case 'B':
			rcvbuf = atoi(optarg);
			break;
		case 'n':
			repeat = atoi(optarg);
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

	if (strcmp(argv[optind], "-") == 0) {
		do_stdin();
		return 0;
	}

	msgcode = argv[optind++];

	if ((p = strtok(msgcode, ":")) == NULL) {
		usage();
		exit(1);
	}

	errno = 0;
	l = strtoul(p, &end, 10);
	if (errno || *end != '\0')
		err(1, "invalid domain");

	domain = l;

	if ((p = strtok(NULL, ":")) == NULL) {
		usage();
		exit(1);
	}

	errno = 0;
	l = strtoul(p, &end, 10);
	if (errno || *end != '\0')
		err(1, "invalid id");

	if (l > UINT16_MAX)
		errx(1, "code out of range");
	code = l;

	if ((p = strtok(NULL, ":")) == NULL) {
		usage();
		exit(1);
	}

	errno = 0;
	l = strtoul(p, &end, 10);
	if (errno || *end != '\0')
		err(1, "invalid variant");

	if (l > UINT16_MAX)
		errx(1, "variant out of range");
	variant = l;

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

	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");
	m_spec = mdr_registry_get(mdr_mkdcv(domain, code, variant));

	r = pmdr_init(&m, NULL, 0, MDR_FNONE);
	if (r == MDR_FAIL)
		err(1, "mdr_init_pack");

	pack(&m, format, (const char **)argv + optind, argc - optind);

	if (target == NULL) {
		pmdr_print(stdout, &m);
		pmdr_free(&m);
		return 0;
	} else if (strcmp(target, "-") == 0) {
		do_stdout(&m);
		return 0;
	}

	do_tls(&m, target, key_path, crt_path);
	return 0;
}
