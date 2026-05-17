#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <mdr/flatconf.h>

struct {
	char      *uid;
	char      *gid;
	char       test_escape_quote[128];
	char       test_escape_backslash[128];
	int        test_boolint;
	uint64_t   test_uint64;
	uint64_t   test_hex;
	int64_t    test_int64;
	char       test_path[PATH_MAX];
	char     **test_path_list;
	uint64_t **test_ulong_list;
} test_conf = {
	NULL,
	NULL,
	"",
	"",
	0,
	1234,
	1234,
	-1234,
	"/tmp/meh",
	NULL,
	NULL
};

struct flatconf flatconf_vars[] = {
	{
		"uid",
		FLATCONF_ALLOCSTRING,
		&test_conf.uid,
		0
	},
	{
		"gid",
		FLATCONF_ALLOCSTRING,
		&test_conf.gid,
		0
	},
	{
		"test_escape_quote",
		FLATCONF_STRING,
		&test_conf.test_escape_quote,
		sizeof(test_conf.test_escape_quote)
	},
	{
		"test_escape_backslash",
		FLATCONF_STRING,
		&test_conf.test_escape_backslash,
		sizeof(test_conf.test_escape_backslash)
	},
	{
		"test_boolint",
		FLATCONF_BOOLINT,
		&test_conf.test_boolint,
		sizeof(test_conf.test_boolint)
	},
	{
		"test_uint64",
		FLATCONF_ULONG,
		&test_conf.test_uint64,
		sizeof(test_conf.test_uint64)
	},
	{
		"test_hex",
		FLATCONF_ULONG,
		&test_conf.test_hex,
		sizeof(test_conf.test_hex)
	},
	{
		"test_int64",
		FLATCONF_LONG,
		&test_conf.test_int64,
		sizeof(test_conf.test_int64)
	},
	{
		"test_path",
		FLATCONF_STRING,
		test_conf.test_path,
		sizeof(test_conf.test_path)
	},
	{
		"test_path_list",
		FLATCONF_ALLOCSTRINGLIST,
		&test_conf.test_path_list,
		0
	},
	{
		"test_ulong_list",
		FLATCONF_ALLOCULONGLIST,
		&test_conf.test_ulong_list,
		0
	},
	FLATCONF_LAST
};

int
main()
{
	int i;

	switch (flatconf_read("flatconf_test.conf", flatconf_vars, NULL)) {
	case 0:
		/* Success */
		break;
	case 1:
		errx(1, "flatconf: configuration is not valid");
	case 2:
		errx(1, "flatconf: memory exhausted by parser");
	default:
		err(1, "flatconf_read");
	}

	printf("uid: %s\n", test_conf.uid);
	printf("gid: %s\n", test_conf.gid);
	printf("test_escape_quote: %s\n", test_conf.test_escape_quote);
	printf("test_escape_backslash: %s\n", test_conf.test_escape_backslash);
	printf("test_uint64: %lu\n", test_conf.test_uint64);
	printf("test_boolint: %d\n", test_conf.test_boolint);
	printf("test_uint64: %lu\n", test_conf.test_uint64);
	printf("test_hex: %lx\n", test_conf.test_hex);
	printf("test_int64: %ld\n", test_conf.test_int64);
	printf("test_path: %s\n", test_conf.test_path);

	printf("test_path_list:");
	for (i = 0; test_conf.test_path_list &&
	    test_conf.test_path_list[i] != NULL; i++) {
		printf(" %s", test_conf.test_path_list[i]);
	}
	printf("\n");

	printf("test_ulong_list:");
	for (i = 0; test_conf.test_ulong_list &&
	    test_conf.test_ulong_list[i] != NULL; i++) {
		printf(" %lu", *test_conf.test_ulong_list[i]);
	}
	printf("\n");

	flatconf_free(flatconf_vars);

	return 0;
}
