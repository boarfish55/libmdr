/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util.h"
#include "xlog.h"

struct spawnmsg {
	int   status;
	pid_t child;
};

int
daemonize(const char *program, const char *pid_path, int nochdir, int noclose, struct xerr *e)
{
	pid_t pid;
	int   pid_fd;
	char  pid_line[32];
	int   null_fd;

	if ((pid_fd = open(pid_path,
	    O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC, 0644)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "open %s", pid_path);

	if (flock(pid_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK)
			return XERRF(e, XLOG_ERRNO, errno,
			    "pid file %s is already locked; "
			    "is another instance running?", pid_path);
		return XERRF(e, XLOG_ERRNO, errno, "flock %s", pid_path);
	}

	if ((pid = fork()) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fork");

	if (pid > 0)
		exit(0);

	if (setsid() == -1) {
		xlog_strerror(LOG_ERR, errno, "setsid");
		exit(1);
	}

	xlog_init(program, NULL, NULL, 1);

	if (!nochdir && chdir("/") == -1) {
		xlog_strerror(LOG_ERR, errno, "chdir");
		exit(1);
	}

	if (!noclose) {
		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			xlog_strerror(LOG_ERR, errno, "open /dev/null");
			exit(1);
		}

		dup2(null_fd, STDIN_FILENO);
		dup2(null_fd, STDOUT_FILENO);
		dup2(null_fd, STDERR_FILENO);
		if (null_fd > 2)
			close(null_fd);
	}

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(pid_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "write %s", pid_path);
		exit(1);
	}

	if (fsync(pid_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "fsync");
		exit(1);
	}

	/* We never close pid_fd, to prevent concurrent executions. */

	return 0;
}

int
drop_privileges(const char *user, const char *group, struct xerr *e)
{
	struct group  *gr;
	struct passwd *pw;

	if (group != NULL) {
		if ((gr = getgrnam(group)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno,
			    "getgrnam %s", group);

		if (setgid(gr->gr_gid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setgid");
		if (setegid(gr->gr_gid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setegid");
	}

	if (user != NULL) {
		if ((pw = getpwnam(user)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "getpwnam %s", user);

		if (setuid(pw->pw_uid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setuid");
		if (seteuid(pw->pw_uid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "seteuid");
	}
	return 0;
}

void
close_x(int fd, const char *fd_name, const char *fn, int line)
{
	if (close(fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s:%d: close(%s)",
		    fn, line, fd_name);
}

ssize_t
readall(int fd, void *buf, size_t count)
{
        ssize_t r;
        ssize_t n = 0;

        while (n < count) {
                r = read(fd, buf + n, count - n);
                if (r == -1) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                } else if (r == 0) {
                        return n;
                }
                n += r;
        }
        return n;
}

ssize_t
writeall(int fd, const void *buf, size_t count)
{
	ssize_t w;
	ssize_t n = 0;

	while (n < count) {
		w = write(fd, buf + n, count - n);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n += w;
	}
	return n;
}

static void
spawnproc_reap(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
}

int
spawnproc_init(struct spawnproc *sp, const char *execpromises, char **perms)
{
	int                sv[2], r;
	pid_t              pid;
#ifdef __OpenBSD__
	char              *path;
	int                i;
#endif
	char              *buf, *a, *start, *user = NULL, *group = NULL;
	char             **argv, **tmp;
	int                argvlen, argvi;
	size_t             sz;
	struct sigaction   act;
	long               max;
	struct xerr        e;
	int                fds[2];
	struct spawnmsg    smsg;
	struct iovec       iov[1];
	struct msghdr      msg;
	struct cmsghdr    *cmsg;
	union {
		struct cmsghdr hdr;
		unsigned char  buf[CMSG_SPACE(sizeof(int) * 2)];
	} cmsgbuf;

	if ((max = sysconf(_SC_ARG_MAX)) == -1)
		return -1;
	/*
	 * We want at least twice _SC_ARG_MAX to allow for this many
	 * arguments plus the separator. We also want a bit of extra space
	 * for uid/gid.
	 */
	max = (max * 2) + (32 * 2);

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) == -1)
		return -1;

	sp->sock = sv[0];

	if ((pid = fork()) == -1) {
		return -1;
	} else if (pid > 0) {
		close(sv[1]);
		return 0;
	}
	close(sv[0]);

	setproctitle("executor");

	if (chdir("/") == -1)
		return -1;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = spawnproc_reap;
	if (sigaction(SIGCHLD, &act, NULL) == -1 ||
	    sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1)
		return -1;
#ifdef __OpenBSD__
	if (unveil("/dev/null", "rw") == -1 ||
	    unveil("/etc/group", "r") == -1 ||
	    unveil("/etc/passwd", "r") == -1 ||
	    unveil("/etc/pwd.db", "r") == -1 ||
	    unveil("/usr/libexec/ld.so", "r") == -1 ||
	    unveil("/usr/lib", "r") == -1)
		return -1;
	for (i = 0; perms && perms[i] != NULL; i++) {
		if ((path = strchr(perms[i], '=')) == NULL) {
			errno = EINVAL;
			return -1;
		} else {
			*path++ = '\0';
		}
		if (unveil(path, perms[i]) == -1)
			return -1;
	}
	if (pledge("stdio rpath id proc exec sendfd", execpromises) == -1)
		return -1;
#endif
	if ((buf = malloc(max)) == NULL)
		return -1;
	argvlen = 16;
	if ((argv = reallocarray(NULL, argvlen, sizeof(char *))) == NULL) {
		free(buf);
		return -1;
	}

	for (;;) {
		r = readall(sv[1], &sz, sizeof(size_t));
		if (r == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: readall", __func__);
			exit(1);
		}
		if (r == 0) {
			xlog(LOG_NOTICE, NULL, "%s: socket closed; exiting",
			    __func__);
			goto end;
		}
		if (sz > LONG_MAX || sz > max) {
			xlog(LOG_ERR, NULL, "%s: command too long", __func__);
			exit(1);
		}

		r = readall(sv[1], buf, sz);
		if (r == -1) {
			xlog_strerror(LOG_ERR, errno, "%s: readall", __func__);
			exit(1);
		}
		if (r == 0) {
			xlog(LOG_NOTICE, NULL, "%s: socket closed; exiting",
			    __func__);
			goto end;
		}

		for (a = buf, start = a, argvi = 0; a - buf < sz; a++) {
			if (*a != '\0')
				continue;
			if (argvi == 0) {
				user = start;
				start = a + 1;
				argvi++;
				continue;
			} else if (argvi == 1) {
				group = start;
				start = a + 1;
				argvi++;
				continue;
			}

			if (argvi + 1 >= argvlen) {
				argvlen *= 2;
				tmp = realloc(argv, argvlen * sizeof(char *));
				if (tmp == NULL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: realloc", __func__);
					exit(1);
				}
				if (tmp != argv)
					argv = tmp;
			}
			argv[argvi - 2] = start;
			argvi++;
			start = a + 1;
		}
		/*
		 * We should have enough space for NULL since we realloc() at
		 * argvi + 1.
		 */
		argv[argvi - 2] = NULL;

		smsg.status = spawn(argv, &smsg.child, &fds[0], &fds[1],
		    user, group, xerrz(&e));
		if (smsg.status == -1) {
			xlog(LOG_ERR, &e, "%s: spawn", __func__);
			if (e.sp == XLOG_ERRNO)
				smsg.status = e.code;
			fds[0] = -1;
			fds[1] = -1;
			smsg.child = 0;
		}
		iov[0].iov_base = &smsg;
		iov[0].iov_len = sizeof(smsg);
		bzero(&msg, sizeof(msg));
		bzero(&cmsgbuf, sizeof(cmsgbuf));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));
again:
		if (sendmsg(sv[1], &msg, 0) == -1) {
			if (errno == -1)
				goto again;
			xlog_strerror(LOG_ERR, errno, "%s: sendmsg (%d)",
			    __func__, errno);
			exit(1);
		}
		close(fds[0]);
		close(fds[1]);
	}
end:
	free(buf);
	free(argv);
	exit(0);

	/* Never reached */
	return 0;
}

int
spawnproc_close(struct spawnproc *sp)
{
	return close(sp->sock);
}

int
spawnproc_exec(struct spawnproc *sp, char *const argv[], pid_t *cpid,
    int *in, int *out, const char *user, const char *group, struct xerr *e)
{
	char            *buf, *p;
	size_t           len = 0;
	int              r, received, i;
	/*
	 * Give enough room for ARG_MAX and a uid/gid, each with accompaying
	 * \0 character.
	 */
	long             max;
	int              fds[2];
	struct spawnmsg  smsg;
	struct msghdr    msg;
	struct cmsghdr  *cmsg;
	struct iovec     iov[1];
	union {
		struct cmsghdr hdr;
		unsigned char  buf[CMSG_SPACE(sizeof(int) * 2)];
	} cmsgbuf;

	if ((max = sysconf(_SC_ARG_MAX)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "sysconf(_SC_ARG_MAX)");
	max = (max * 2) + (32 * 2);

	if (argv == NULL || argv[0] == NULL)
		return XERRF(e, XLOG_APP, XLOG_INVALID, "argv is empty");

	if (user != NULL)
		len += strlen(user) + 1;
	if (group != NULL)
		len += strlen(group) + 1;
	for (i = 0; argv[i] != NULL; i++) {
		len += strlen(argv[i]) + 1;
		if (len > max)
			return XERRF(e, XLOG_APP, XLOG_INVALID,
			    "total length of command exceeds allowed value");
	}

	if ((buf = malloc(len)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");
	p = buf;

	if (user != NULL) {
		len = strlen(user);
		memcpy(p, user, len);
		p += len;
		*p++ = '\0';
	}

	if (group != NULL) {
		len = strlen(group);
		memcpy(p, group, len);
		p += len;
		*p++ = '\0';
	}

	for (i = 0; argv[i] != NULL; i++) {
		len = strlen(argv[i]);
		memcpy(p, argv[i], len);
		p += len;
		*p++ = '\0';
	}

	len = p - buf;
	if (writeall(sp->sock, &len, sizeof(len)) == -1) {
		free(buf);
		return XERRF(e, XLOG_ERRNO, errno, "writeall");
	}
	if (writeall(sp->sock, buf, len) == -1) {
		free(buf);
		return XERRF(e, XLOG_ERRNO, errno, "writeall");
	}
	free(buf);

	iov[0].iov_base = &smsg;
	iov[0].iov_len = sizeof(smsg);

	bzero(&msg, sizeof(msg));
	bzero(&cmsgbuf, sizeof(cmsgbuf));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	received = 0;
	while (received < sizeof(int)) {
		if ((r = recvmsg(sp->sock, &msg,
		    MSG_WAITALL|MSG_CMSG_CLOEXEC)) == -1) {
			if (errno == EINTR)
				continue;
			return XERRF(e, XLOG_ERRNO, errno, "recvmsg");
		}

		if (r == 0)
			return XERRF(e, XLOG_APP, XLOG_EOF, "recvmsg");

		received += r;
		if (received < sizeof(smsg)) {
			iov[0].iov_base = ((char *)&smsg) + received;
			iov[0].iov_len = sizeof(smsg) - received;
		}
	}
	if (cpid != NULL)
		*cpid = smsg.child;
	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC))
		return XERRF(e, XLOG_APP, XLOG_IO,
		    "recvmsg: control message truncated");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(fds)) &&
		    cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));
			*in = fds[0];
			*out = fds[1];
		}
		break;
	}

	return smsg.status;
}

int
spawn(char *const argv[], pid_t *pid, int *in, int *out, const char *user,
    const char *group, struct xerr *e)
{
	int   p_in[2];
	int   p_out[2];
	int   null_fd;

	if (pipe(p_in) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pipe");
	*in = p_in[1];

	if (pipe(p_out) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "pipe");
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		return -1;
	}
	*out = p_out[0];

	if ((*pid = fork()) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fork");
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		CLOSE_X(p_out[1]);
		return -1;
	} else if (*pid == 0) {
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		if (p_in[0] != STDIN_FILENO) {
			if (dup2(p_in[0], STDIN_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				exit(1);
			}
			CLOSE_X(p_in[0]);
		}
		if (p_out[1] != STDOUT_FILENO) {
			if (dup2(p_out[1], STDOUT_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				exit(1);
			}
			CLOSE_X(p_out[1]);
		}

		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			xlog_strerror(LOG_ERR, errno, "open /dev/null");
			exit(1);
		}
		dup2(null_fd, STDERR_FILENO);
		if (null_fd > 2)
			close(null_fd);

		if (geteuid() == 0) {
			if (drop_privileges(user, group, xerrz(e)) == -1) {
				xlog(LOG_ERR, e, "drop_privileges");
				exit(1);
			}
		}

		if (execv(argv[0], argv) == -1) {
			xlog_strerror(LOG_ERR, errno, "execv: %s", argv[0]);
			exit(1);
		}
	}

	CLOSE_X(p_in[0]);
	CLOSE_X(p_out[1]);

	return 0;
}

char **
strarray_alloc(size_t n, size_t len)
{
	int      i;
	char   **p;
	size_t   sz;

	sz = ((n + 1) * sizeof(char *)) + (n * len);
	if ((p = malloc(sz)) == NULL)
		return NULL;

	for (i = 0; i < n; i++)
		p[i] = (char *)p + ((n + 1) * sizeof(char *)) + (i * len);
	p[i] = NULL;
	bzero((char *)p + ((n + 1) * sizeof(char *)), n * len);

	return p;
}

char **
strarray_add(char **a, const char *str)
{
	int      i, j;
	size_t   sz;
	size_t   len = strlen(str) + 1;
	char    *p, *start;

	if (a == NULL) {
		if ((a = malloc((sizeof(char *) * 2) + len)) == NULL)
			return NULL;
		strlcpy(((char *)a) + (sizeof(char *) * 2), str, len);
		a[0] = ((char *)a) + (sizeof(char *) * 2);
		a[1] = NULL;
		return a;
	}

	for (sz = sizeof(char *), i = 0; a[i] != NULL; i++)
		sz += sizeof(char *) + strlen(a[i]) + 1;

	if ((a = realloc(a, sz + sizeof(char *) + len)) == NULL)
		return NULL;

	memmove(((char *)a) + (sizeof(char *) * (i + 2)),
	    ((char *)a) + (sizeof(char *) * (i + 1)),
	    sz - (sizeof(char *) * (i + 1)));

	for (j = 0, p = ((char *)a) + (sizeof(char *) * (i + 2)), start = p;
	    p - (char *)a < sz + sizeof(char *); p++) {
		if (*p == '\0') {
			a[j++] = start;
			start = p + 1;
		}
	}

	strlcpy(((char *)a) + sz + sizeof(char *), str, len);

	a[i] = ((char *)a) + sz + sizeof(char *);
	a[i + 1] = NULL;

	return a;
}
