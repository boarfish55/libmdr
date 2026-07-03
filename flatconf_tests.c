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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mdr/flatconf.h>

static const char tmpconf[] = "flatconf_tests.conf.tmp";

struct test_status
{
	char *msg;
	enum {
		OK = 0,
		FAIL,
		SKIPPED
	} status;
} test_status;

const char *status_description[] = {
	"OK",
	"FAIL",
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

/*
 * Parse errors are expected in many tests here; swallow them so the
 * output stays readable, but keep the last one for diagnostics.
 */
static char last_parse_error[LINE_MAX];

static void
quiet_err(const char *msg)
{
	strlcpy(last_parse_error, msg, sizeof(last_parse_error));
}

static void
write_conf(const char *content)
{
	FILE *f;

	if ((f = fopen(tmpconf, "w")) == NULL)
		err(1, "fopen %s", tmpconf);
	if (fputs(content, f) == EOF)
		err(1, "fputs %s", tmpconf);
	if (fclose(f) == EOF)
		err(1, "fclose %s", tmpconf);
}

static struct test_status *
test_reference_conf()
{
	struct {
		char      *uid;
		char      *gid;
		char       escape_quote[128];
		char       escape_backslash[128];
		int        boolint;
		uint64_t   u64;
		uint64_t   hex;
		int64_t    i64;
		char       path[PATH_MAX];
		char     **path_list;
		uint64_t **ulong_list;
	} c;
	struct flatconf vars[] = {
		{ "uid",                   FLATCONF_ALLOCSTRING,
		    &c.uid,                0 },
		{ "gid",                   FLATCONF_ALLOCSTRING,
		    &c.gid,                0 },
		{ "test_escape_quote",     FLATCONF_STRING,
		    c.escape_quote,        sizeof(c.escape_quote) },
		{ "test_escape_backslash", FLATCONF_STRING,
		    c.escape_backslash,    sizeof(c.escape_backslash) },
		{ "test_boolint",          FLATCONF_BOOLINT,
		    &c.boolint,            sizeof(c.boolint) },
		{ "test_uint64",           FLATCONF_ULONG,
		    &c.u64,                sizeof(c.u64) },
		{ "test_hex",              FLATCONF_ULONG,
		    &c.hex,                sizeof(c.hex) },
		{ "test_int64",            FLATCONF_LONG,
		    &c.i64,                sizeof(c.i64) },
		{ "test_path",             FLATCONF_STRING,
		    c.path,                sizeof(c.path) },
		{ "test_path_list",        FLATCONF_ALLOCSTRINGLIST,
		    &c.path_list,          0 },
		{ "test_ulong_list",       FLATCONF_ALLOCULONGLIST,
		    &c.ulong_list,         0 },
		FLATCONF_LAST
	};
	int i;

	bzero(&c, sizeof(c));

	if (flatconf_read("flatconf_test.conf", vars, quiet_err) != 0)
		return ERR(errno, "flatconf_read: %s", last_parse_error);

	if (c.uid == NULL || strcmp(c.uid, "plalonde") != 0)
		return ERR(0, "unexpected uid");
	if (c.gid == NULL || strcmp(c.gid, "plalonde") != 0)
		return ERR(0, "unexpected gid");
	if (strcmp(c.escape_quote, "a quote \" was quoted") != 0)
		return ERR(0, "quote was not unescaped correctly");
	if (strcmp(c.escape_backslash, "a backslash \\ was escaped") != 0)
		return ERR(0, "backslash was not unescaped correctly");
	if (c.boolint != 1)
		return ERR(0, "boolint 'true' did not yield 1");
	if (c.u64 != UINT64_MAX)
		return ERR(0, "unexpected uint64 value");
	if (c.hex != 0xffffffff)
		return ERR(0, "unexpected hex value");
	if (c.i64 != INT64_MIN)
		return ERR(0, "unexpected int64 value");
	if (strcmp(c.path, "/home/plalonde") != 0)
		return ERR(0, "unexpected path");

	if (c.path_list == NULL)
		return ERR(0, "path list was not allocated");
	for (i = 0; c.path_list[i] != NULL; i++)
		;
	if (i != 4)
		return ERR(0, "expected 4 paths in list, got %d", i);
	if (strcmp(c.path_list[0], "/home/plalonde") != 0 ||
	    strcmp(c.path_list[1], "/tmp/yo") != 0 ||
	    strcmp(c.path_list[2], "/tmp/ya") != 0)
		return ERR(0, "path list elements out of order");
	if (strncmp(c.path_list[3], "/p/p/p", 6) != 0)
		return ERR(0, "unexpected long path");

	if (c.ulong_list == NULL)
		return ERR(0, "ulong list was not allocated");
	for (i = 0; c.ulong_list[i] != NULL; i++)
		;
	if (i != 3)
		return ERR(0, "expected 3 ulongs in list, got %d", i);
	if (*c.ulong_list[0] != 123 || *c.ulong_list[1] != 456 ||
	    *c.ulong_list[2] != 0xff)
		return ERR(0, "ulong list elements out of order");

	flatconf_free(vars);
	if (c.uid != NULL || c.gid != NULL || c.path_list != NULL ||
	    c.ulong_list != NULL)
		return ERR(0, "flatconf_free did not reset pointers");

	return success();
}

static struct test_status *
test_scalar_empty_list()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	write_conf("num = []\n");
	if (flatconf_read(tmpconf, vars, quiet_err) == 0)
		return ERR(0, "empty list on a scalar should fail");
	return success();
}

static struct test_status *
test_scalar_multi_list()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	write_conf("num = [ 1 2 3 ]\n");
	if (flatconf_read(tmpconf, vars, quiet_err) == 0)
		return ERR(0, "multi-value list on a scalar should fail");
	return success();
}

static struct test_status *
test_scalar_single_list()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	write_conf("num = [ 7 ]\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "single-value list on a scalar should parse: %s",
		    last_parse_error);
	if (num != 7)
		return ERR(0, "expected 7, got %" PRIu64, num);
	return success();
}

static struct test_status *
test_lexer_reset()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	/*
	 * A parse failure in the middle of a token must not poison the
	 * next flatconf_read(); the lexer used to stay in ST_STRING and
	 * silently consume the entire next file.
	 */
	write_conf("num = \"never closed\n");
	if (flatconf_read(tmpconf, vars, quiet_err) == 0)
		return ERR(0, "unterminated string should fail");

	write_conf("num = 42\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "parse after a failed parse should succeed: %s",
		    last_parse_error);
	if (num != 42)
		return ERR(0, "expected 42, got %" PRIu64, num);
	return success();
}

static struct test_status *
test_free_then_reread()
{
	char           *astr = NULL;
	struct flatconf vars[] = {
		{ "astr", FLATCONF_ALLOCSTRING, &astr, 0 },
		FLATCONF_LAST
	};

	write_conf("astr = \"hello\"\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "first read failed: %s", last_parse_error);
	if (astr == NULL || strcmp(astr, "hello") != 0)
		return ERR(0, "unexpected value on first read");

	flatconf_free(vars);
	if (astr != NULL)
		return ERR(0, "flatconf_free did not reset the pointer");

	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "re-read after free failed: %s",
		    last_parse_error);
	if (astr == NULL || strcmp(astr, "hello") != 0)
		return ERR(0, "unexpected value on re-read");

	flatconf_free(vars);
	return success();
}

static struct test_status *
test_duplicate_assignment()
{
	char           *astr = NULL;
	char          **slist = NULL;
	struct flatconf vars[] = {
		{ "astr",  FLATCONF_ALLOCSTRING,     &astr,  0 },
		{ "slist", FLATCONF_ALLOCSTRINGLIST, &slist, 0 },
		FLATCONF_LAST
	};

	/* Last assignment wins; the previous allocations are freed. */
	write_conf("astr = \"one\"\n"
	    "astr = \"two\"\n"
	    "slist = [ \"a\" \"b\" ]\n"
	    "slist = [ \"c\" ]\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "flatconf_read failed: %s", last_parse_error);
	if (astr == NULL || strcmp(astr, "two") != 0)
		return ERR(0, "last string assignment did not win");
	if (slist == NULL || slist[0] == NULL ||
	    strcmp(slist[0], "c") != 0 || slist[1] != NULL)
		return ERR(0, "last list assignment did not win");

	flatconf_free(vars);
	return success();
}

static struct test_status *
test_empty_allocstring()
{
	char           *astr = NULL;
	struct flatconf vars[] = {
		{ "astr", FLATCONF_ALLOCSTRING, &astr, 0 },
		FLATCONF_LAST
	};

	write_conf("astr = \"\"\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "flatconf_read failed: %s", last_parse_error);
	if (astr == NULL || astr[0] != '\0')
		return ERR(0, "expected an allocated empty string");

	/* An empty string is still an allocation and must be freed. */
	flatconf_free(vars);
	if (astr != NULL)
		return ERR(0, "flatconf_free did not free the empty string");
	return success();
}

static struct test_status *
test_list_reassign_empty()
{
	char          **slist = NULL;
	struct flatconf vars[] = {
		{ "slist", FLATCONF_ALLOCSTRINGLIST, &slist, 0 },
		FLATCONF_LAST
	};

	/* Reassigning to [] resets the variable to its unassigned state. */
	write_conf("slist = [ \"a\" \"b\" ]\n"
	    "slist = []\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "flatconf_read failed: %s", last_parse_error);
	if (slist != NULL)
		return ERR(0, "empty reassignment did not reset the list");

	flatconf_free(vars);
	return success();
}

static struct test_status *
test_token_adjacency()
{
	uint64_t        num = 0;
	char          **slist = NULL;
	uint64_t      **ulist = NULL;
	struct flatconf vars[] = {
		{ "num",   FLATCONF_ULONG,           &num,   sizeof(num) },
		{ "slist", FLATCONF_ALLOCSTRINGLIST, &slist, 0 },
		{ "ulist", FLATCONF_ALLOCULONGLIST,  &ulist, 0 },
		FLATCONF_LAST
	};

	/* '=' and ']' terminate words and numbers without whitespace. */
	write_conf("num=42\n"
	    "slist = [a b]\n"
	    "ulist = [ 1 2]\n");
	if (flatconf_read(tmpconf, vars, quiet_err) != 0)
		return ERR(0, "flatconf_read failed: %s", last_parse_error);
	if (num != 42)
		return ERR(0, "num=42 did not parse");
	if (slist == NULL || slist[0] == NULL || slist[1] == NULL ||
	    strcmp(slist[0], "a") != 0 || strcmp(slist[1], "b") != 0 ||
	    slist[2] != NULL)
		return ERR(0, "unexpected string list");
	if (ulist == NULL || ulist[0] == NULL || ulist[1] == NULL ||
	    *ulist[0] != 1 || *ulist[1] != 2 || ulist[2] != NULL)
		return ERR(0, "unexpected ulong list");

	flatconf_free(vars);
	return success();
}

static struct test_status *
test_missing_trailing_newline()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	write_conf("num = 42");
	if (flatconf_read(tmpconf, vars, quiet_err) == 0)
		return ERR(0, "statement without trailing newline "
		    "should fail");
	return success();
}

static struct test_status *
test_unknown_variable()
{
	uint64_t        num = 0;
	struct flatconf vars[] = {
		{ "num", FLATCONF_ULONG, &num, sizeof(num) },
		FLATCONF_LAST
	};

	write_conf("nope = 1\n");
	if (flatconf_read(tmpconf, vars, quiet_err) == 0)
		return ERR(0, "unknown variable should fail");
	return success();
}

static struct flatconf_test {
	char                description[256];
	struct test_status *(*fn)();
} tests[] = {
	{
		"reference config",
		&test_reference_conf
	},
	{
		"empty list on scalar",
		&test_scalar_empty_list
	},
	{
		"multi-value list on scalar",
		&test_scalar_multi_list
	},
	{
		"single-value list on scalar",
		&test_scalar_single_list
	},
	{
		"lexer reset between reads",
		&test_lexer_reset
	},
	{
		"free then re-read",
		&test_free_then_reread
	},
	{
		"duplicate assignment",
		&test_duplicate_assignment
	},
	{
		"empty allocstring",
		&test_empty_allocstring
	},
	{
		"list reassigned to empty",
		&test_list_reassign_empty
	},
	{
		"token adjacency",
		&test_token_adjacency
	},
	{
		"missing trailing newline",
		&test_missing_trailing_newline
	},
	{
		"unknown variable",
		&test_unknown_variable
	},
	{
		"",
		NULL
	}
};

int
main(int argc, char **argv)
{
	struct flatconf_test *t;
	struct test_status   *s;
	int                   status = 0;

	for (t = tests; t->fn != NULL; t++) {
		if (argc > 1 &&
		    strstr(t->description, argv[1]) == NULL)
			continue;

		s = t->fn();
		printf("[%s] %s\n", status_description[s->status],
		    t->description);
		if (s->msg && (s->status == FAIL)) {
			status = 1;
			printf("\n%s\n\n", s->msg);
			free(s->msg);
		}
	}
	unlink(tmpconf);
	return status;
}
