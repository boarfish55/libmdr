/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef MDR_UTIL_H
#define MDR_UTIL_H

#include <mdr/xlog.h>

__BEGIN_DECLS

struct spawnproc {
	int sock;
};

int daemonize(const char *, const char *, int, int, struct xerr *);
int drop_privileges(const char *, const char *, struct xerr *);
int spawnproc_init(struct spawnproc *, int, const char *, char **);
int spawnproc_close(struct spawnproc *);
int spawnproc_exec(struct spawnproc *, char *const[], pid_t *, int *, int *,
        const char *, const char *, struct xerr *);

ssize_t readall(int, void *, size_t);
ssize_t writeall(int, const void *, size_t);

#define CLOSE_X(fd) close_x(fd, #fd, __func__, __LINE__)
void   close_x(int, const char *, const char *, int);
int    spawn(char *const[], pid_t *, int *, int *, const char *,
           const char *, struct xerr *);

char **strarray_alloc(size_t, size_t);
char **strarray_add(char **, const char *);

__END_DECLS

#endif
