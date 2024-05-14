#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdr.h"

const char *program = "mdrc";

int debug = 0;

void
usage()
{
	printf("%s: [-dh] "
	    "<send namespace:id:version> <format> <args>\n",
	    program);
}

void
pack(struct mdr *m, const char *spec, const char **args, int count)
{
	int             finish = 0;
	const char     *p, *prev;
	char           *end;
	const char     *bytes;
	const char    **a;
	uint64_t        bytes_sz;
	uint64_t        bits;
	unsigned long   l;
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
			bytes = *a++;
			bytes_sz = strtoull(*a, &end, 10);
			if (bytes_sz == ULLONG_MAX || *end != '\0')
				errx(1, "invalid value");
			if (mdr_pack_bytes(m, bytes, bytes_sz) == MDR_FAIL)
				err(1, "mdr_pack_bytes");
			a++;
		} else if (strcmp(spbuf, "s") == 0) {
			if (mdr_pack_string(m, *a++) == MDR_FAIL)
				err(1, "mdr_pack_string");
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2)
				errx(1, "invalid format spec");

			if ((bits = strtoull(spbuf + 1, &end, 10))
			    == ULLONG_MAX || *end != '\0')
				errx(1, "invalid format spec");

			switch (bits) {
			case 8:
				l = strtoul(*a, &end, 10);
				if (l == ULONG_MAX || *end != '\0')
					errx(1, "invalid value");
				if (mdr_pack_uint8(m, l) == MDR_FAIL)
					errx(1, "invalid value");
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
	struct mdr     m;

	while ((opt = getopt(argc, argv, "hd")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'd':
			debug = 1;
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

	printf("namespace: %u, id: %u, version: %u\n",
	    namespace, id, version);

	r = mdr_pack_hdr(&m, 0, namespace, id, version, NULL, 0);
	if (r == MDR_FAIL)
		err(1, "mdr_pack_hdr");

	pack(&m, format, (const char **)argv + optind, argc - optind);
	// TODO send...

	mdr_free(&m);

	// TODO: unpack hdr then dump payload in hex

	return 0;
}
