#include <openssl/crypto.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <mdr/xlog.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int
some_func8(struct xerr *e)
{
	return XERRF(e, XLOG_ERRNO, ENOENT, "some file op: %s",
	    "somefile");
}

static int
some_func7(struct xerr *e)
{
	some_func8(e);
	return XERR_PUSH(e);
}

static int
some_func6(struct xerr *e)
{
	some_func7(e);
	return XERR_PUSH(e);
}

static int
some_func5(struct xerr *e)
{
	some_func6(e);
	return XERR_PUSH(e);
}

static int
some_func4(struct xerr *e)
{
	some_func5(e);
	return XERR_PUSH(e);
}

static int
some_func3(struct xerr *e)
{
	some_func4(e);
	return XERR_PUSH(e);
}

static int
some_func2(struct xerr *e)
{
	some_func3(e);
	return XERR_PUSH(e);
}

static int
some_func1(struct xerr *e)
{
	some_func2(e);
	return XERR_PUSH(e);
}

static int
some_func0(struct xerr *e)
{
	some_func1(e);
	return XERR_PUSH(e);
}

static struct xerr
direct_error()
{
	struct xerr e;
	XERRF(&e, XLOG_EAI, EAI_FAMILY, "I am a failure");
	return e;
}

static struct xerr
direct_error2()
{
	struct xerr e;
	XERRF(&e, XLOG_SSL, 8, "I am an SSL failure");
	return e;
}

int
main()
{
	struct xerr e = XERR_INITIALIZER;
	struct xerr e2, e3, e5;
	struct xerr e4 = XERR_INITIALIZER;

	some_func0(&e);

	xlog_init("xlog_tests", NULL, NULL, 1);
	xlog(LOG_ERR, &e, "well we failed here at line: %d (xerr sz=%zu)",
	    __LINE__, sizeof(e));

	e2 = direct_error();
	xlog(LOG_ERR, &e2, __func__);

	e3 = direct_error2();
	xerr_print(&e3);

	/*
	 * Regression: printing an xerr that carries no error must not
	 * crash; stack[0] used to be NULL (XERR_INITIALIZER) or stale
	 * (xerrz() on uninitialized memory).
	 */
	xerr_print(&e4);
	xlog(LOG_ERR, &e4, "empty xerr with a format string");
	memset(&e5, 0xa5, sizeof(e5));
	xerr_print(xerrz(&e5));

	OPENSSL_cleanup();
	return 0;
}
