/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <mdr/xlog.h>

const struct module_dbg_map_entry module_dbg_map[] = {
	{ "all",       XLOG_ALL },
	{ "",          0x0000 }
};

static xlog_mask_t  debug_mask = 0;
FILE               *log_file = NULL;
static int          log_level = LOG_INFO;

static const char *
priostr(int prio)
{
	switch (prio) {
	case LOG_EMERG:
		return "G";
	case LOG_ALERT:
		return "A";
	case LOG_CRIT:
		return "C";
	case LOG_ERR:
		return "E";
	case LOG_WARNING:
		return "W";
	case LOG_NOTICE:
		return "N";
	case LOG_INFO:
		return "I";
	case LOG_DEBUG:
		return "D";
	default:
		return "U";
	}
}

static const char *
spacestr(int sp)
{
	switch (sp) {
	case XLOG_NONE:
		return "NONE";
	case XLOG_APP:
		return "APP";
	case XLOG_ERRNO:
		return "ERRNO";
	case XLOG_SSL:
		return "SSL";
	case XLOG_EAI:
		return "EAI";
	case XLOG_DB:
		return "DB";
	default:
		return "?";
	}
}

struct xerr *
xerrz(struct xerr *e)
{
	if (e == NULL)
		return NULL;

	e->sp = 0;
	e->code = 0;
	e->depth = 0;
	e->msg[0] = '\0';
	return e;
}

static int
xerr_assemble(const struct xerr *e, char *dst, size_t dst_sz,
    const char *fmt, va_list *ap)
{
	int     i, len = 0;
	char    errmsg[128];

	if (dst == NULL || dst_sz < 16)
		return -1;

	dst[0] = '\0';

	if (e == NULL)
		return 0;

	if (fmt != NULL) {
		len = vsnprintf(dst, dst_sz, fmt, *ap);
		if (len >= dst_sz) {
			dst[dst_sz - 2] = '*';
			return len;
		}
	}

	if (strlcat(dst, ">>", dst_sz) >= dst_sz) {
		dst[dst_sz - 2] = '*';
		return dst_sz;
	}
	len += 2;

	if (e->depth >= XERR_MAX_DEPTH) {
		if (strlcat(dst, "*", dst_sz) >= dst_sz) {
			dst[dst_sz - 2] = '*';
			return dst_sz;
		}
	}

	for (i = MIN(e->depth, XERR_MAX_DEPTH - 1); i >= 0; i--) {
		if (strlcat(dst, e->stack[i], dst_sz) >= dst_sz) {
			strlcpy(dst, "*: ", dst_sz);
			break;
		}
		if (strlcat(dst, ">>", dst_sz) >= dst_sz) {
			strlcpy(dst, "*: ", dst_sz);
			break;
		}
	}

	if (strlcat(dst, " ", dst_sz) >= dst_sz)
		strlcpy(dst, "*: ", dst_sz);

	len = strlen(dst);

	if (e->sp == XLOG_ERRNO && e->code != 0) {
		strerror_r(e->code, errmsg, sizeof(errmsg));
		len += snprintf(dst + len, dst_sz - len, "%s: %s",
		    e->msg, errmsg);
	} else if (e->sp == XLOG_EAI && e->code != 0) {
		len += snprintf(dst + len, dst_sz - len, "%s: %s",
		    e->msg, gai_strerror(e->code));
	} else if (e->sp == XLOG_SSL && e->code != 0) {
		ERR_error_string_n(e->code, errmsg, sizeof(errmsg));
		len += snprintf(dst + len, dst_sz - len, "%s: %s",
		    e->msg, errmsg);
	} else {
		len += snprintf(dst + len, dst_sz - len, "%s", e->msg);
	}

	return len;
}

int
xerrf(struct xerr *e, int space, int code, const char *fn,
    const char *fmt, ...)
{
	va_list ap;
	int     written;
	int     status = (space || code) ? -1 : 0;

	if (e == NULL)
		return status;

	e->sp = space;
	e->code = code;
	e->depth = 0;
	e->stack[0] = fn;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';

	return status;
}

int
xerr_fail(const struct xerr *e)
{
	if (e == NULL)
		return 0;

	return (e->sp || e->code) ? -1 : 0;
}

int
xerr_is(const struct xerr *e, int code, int subcode)
{
	if (e == NULL)
		return 0;

	if (e->sp == code && e->code == subcode)
		return 1;

	return 0;
}

static void
xlog_fprintf(const char *fmt, ...)
{
	va_list   ap;
	char      msg[LINE_MAX], t_str[64];
	struct tm tm;
	time_t    t;

	if (log_file == NULL)
		return;

	t = time(NULL);
	if (localtime_r(&t, &tm) == NULL)
		return;

	strftime(t_str, sizeof(t_str), "%FT%R:%S%z", &tm);

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	fprintf(log_file, "%s/%d: %s\n", t_str, getpid(), msg);
	fflush(log_file);
}

int
xlog_init(const char *progname, const char *dbg_spec, const char *logf,
    int perror)
{
	return xlog_init2(progname, LOG_USER, dbg_spec, logf, perror);
}

int
xlog_init2(const char *progname, int facility, const char *dbg_spec,
    const char *logf, int perror)
{
	char                              *dbg, *module, *save;
	const struct module_dbg_map_entry *map;
	int                                opt = LOG_PID;

	if (perror)
		opt |= LOG_PERROR;

	if (logf != NULL && logf[0] != '\0' && log_file == NULL)
		if ((log_file = fopen(logf, "a")) == NULL)
			warn("fopen");

	openlog(progname, opt, facility);
	if (dbg_spec == NULL || *dbg_spec == '\0') {
		setlogmask(LOG_UPTO(LOG_INFO));
		return 0;
	}

	dbg = strdup(dbg_spec);
	if (dbg == NULL)
		return -1;

	log_level = LOG_DEBUG;
	setlogmask(LOG_UPTO(LOG_DEBUG));
	for ((module = strtok_r(dbg, ",", &save)); module;
	    (module = strtok_r(NULL, ",", &save))) {
		for (map = module_dbg_map; *map->name; map++) {
			if (strcmp(map->name, module) == 0) {
				debug_mask |= map->flag;
				syslog(LOG_DEBUG, "enabling %s debug logging",
				    map->name);
				xlog_fprintf("enabling %s debug logging",
				    map->name);
			}
		}
	}
	free(dbg);

	return 0;
}

void
xlog_dbg(xlog_mask_t module, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];

	if (fmt == NULL || (module & debug_mask) == 0)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	syslog(LOG_DEBUG, "{%s} %s", priostr(LOG_DEBUG), msg);
	xlog_fprintf("{%s} %s", priostr(LOG_DEBUG), msg);
}

void
xlog(int priority, const struct xerr *e, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];

	if (priority > log_level)
		return;

	if (e == NULL) {
		if (fmt != NULL) {
			va_start(ap, fmt);
			vsnprintf(msg, sizeof(msg), fmt, ap);
			va_end(ap);
			syslog(priority, "{%s} %s", priostr(priority), msg);
			xlog_fprintf("{%s} %s", priostr(priority), msg);
		}
		return;
	}

	va_start(ap, fmt);
	xerr_assemble(e, msg, sizeof(msg), fmt, &ap);
	va_end(ap);

	syslog(priority, "{%s:%s:%" PRIi64 "} %s",
	    priostr(priority), spacestr(e->sp), e->code, msg);
	xlog_fprintf("{%s:%s:%" PRIi64 "} %s",
	    priostr(priority), spacestr(e->sp), e->code, msg);
}

void
xlog_strerror(int priority, int err, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];
	char    errmsg[256] = "";

	if (priority > log_level)
		return;
	if (fmt == NULL)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	strerror_r(err, errmsg, sizeof(errmsg));
	syslog(priority, "{%s:%s:%d} %s: %s",
	    priostr(priority), spacestr(XLOG_ERRNO), err, msg, errmsg);
	xlog_fprintf("{%s:%s:%d} %s: %s",
	    priostr(priority), spacestr(XLOG_ERRNO), err, msg, errmsg);
}

void
xerr_print(const struct xerr *e)
{
	char msg[LINE_MAX];

	if (e == NULL)
		return;

	xerr_assemble(e, msg, sizeof(msg), NULL, NULL);

	warnx("{%s:%" PRIi64 "} %s", spacestr(e->sp), e->code, msg);
}

int
xerr_push(struct xerr *e, const char *fn)
{
	if (e == NULL)
		return 0;

	if (e->depth < UINT8_MAX)
		e->depth++;

	if (e->depth >= XERR_MAX_DEPTH)
		return xerr_fail(e);

	e->stack[e->depth] = fn;
	return xerr_fail(e);
}
