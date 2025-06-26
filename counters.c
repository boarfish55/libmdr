#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "counters.h"
#include "counter_names.h"
#include "util.h"

int                    arena_count = 0;
struct counters_arena *arenas;
struct counters_arena *current_arena;

int
counters_init(int n_arenas)
{
	struct counters_arena *a;
	int                    i, c;

	arena_count = n_arenas;

	arenas = mmap(NULL, sizeof(struct counters_arena) * n_arenas,
	    PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
	if (arenas == MAP_FAILED)
		return -1;
	current_arena = arenas;

	for (a = arenas, i = 0; i < n_arenas; i++, a++) {
		a->pid = 0;
		for (c = 0; c < COUNTER_LAST; c++) {
			a->c[c].v = 0;
			if (sem_init(&a->c[c].lock, 1, 1) == -1)
				return -1;
		}
	}

	return 0;
}

void
counters_read(const char *path)
{
	int                fd, c;
	struct sockaddr_un addr;
	uint64_t           v[COUNTER_LAST], v_all[COUNTER_LAST];
	ssize_t            r;

	if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		err(1, "connect");

	bzero(v_all, sizeof(v_all));
	for (;;) {
		r = readall(fd, v, sizeof(v));
		if (r == -1)
			err(1, "readall");
		if (r == 0)
			break;

		if (r < sizeof(v))
			errx(1, "readall: short read on counters: %lu < %lu",
			    r, sizeof(v));

		for (c = 0; c < COUNTER_LAST; c++)
			v_all[c] += v[c];
	}
	close(fd);

	for (c = 0; c < COUNTER_LAST; c++)
		printf("%-20s: %lu\n", counter_names[c], v_all[c]);
}

int
counters_set_arena(int idx)
{
	if (idx >= arena_count) {
		errno = EINVAL;
		return -1;
	}
	current_arena = arenas + idx;
	return 0;
}

int
counters_arena_count()
{
	return arena_count;
}

void
counters_set_pid(pid_t pid)
{
	current_arena->pid = pid;
}

int
counters_find_arena(pid_t pid)
{
	int i;
	for (i = 0; i < arena_count; i++) {
		if (arenas[i].pid == pid)
			return i;
	}
	return -1;
}

uint64_t
counters_get(int c)
{
	uint64_t v;

	if (sem_wait(&current_arena->c[c].lock) == -1)
		abort();
	v = current_arena->c[c].v;
	if (sem_post(&current_arena->c[c].lock) == -1)
		abort();
	return v;
}

void
counters_add(int c, uint64_t v)
{
	if (sem_wait(&current_arena->c[c].lock) == -1)
		abort();
	current_arena->c[c].v += v;
	if (sem_post(&current_arena->c[c].lock) == -1)
		abort();
}

void
counters_sub(int c, uint64_t v)
{
	if (sem_wait(&current_arena->c[c].lock) == -1)
		abort();

	if (v >= current_arena->c[c].v)
		current_arena->c[c].v = 0;
	else
		current_arena->c[c].v -= v;

	if (sem_post(&current_arena->c[c].lock) == -1)
		abort();
}

void
counters_incr(int c)
{
	counters_add(c, 1);
}

void
counters_decr(int c)
{
	counters_sub(c, 1);
}
