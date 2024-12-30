#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "counters.h"
#include "counter_names.h"

int                    arena_count = 0;
struct counters_arena *arenas;
struct counters_arena *current_arena;

int
counters_init(const char *path, int n_arenas)
{
	struct counters_arena *a;
	int                    i, fd;

	arena_count = n_arenas;
	if ((fd = shm_open(path, O_CREAT|O_RDWR, 0600)) == -1)
		return -1;

	if (ftruncate(fd, sizeof(struct counters_arena) * n_arenas) == -1)
		return -1;

	arenas = mmap(NULL, sizeof(struct counters_arena) * n_arenas,
	    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (arenas == MAP_FAILED)
		return -1;
	current_arena = arenas;

	for (a = arenas, i = 0; i < n_arenas; i++, a++) {
		bzero(a, sizeof(struct counters_arena));
		if (sem_init(&a->lock_a, 1, 1) == -1)
			return -1;
		if (sem_init(&a->lock_b, 1, 1) == -1)
			return -1;
	}

	return 0;
}

void
counters_read(const char *path)
{
	struct counters_arena *a, *ap;
	int                    fd, c;
	struct stat            st;

	if ((fd = shm_open(path, O_CREAT|O_RDWR, 0600)) == -1)
		err(1, "shm_open");

	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	printf("mdrd counters size: %lu (%lu per arena)\n", st.st_size,
	    sizeof(struct counters_arena));

	a = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (a == MAP_FAILED)
		err(1, "mmap");

	for (ap = a;
	    ap - a < (st.st_size / sizeof(struct counters_arena)); ap++) {
		printf(
		    "%-20s: %d\n"
		    "%-20s: %d\n",
		    "pid", ap->pid, "b", ap->b);

		if (ap->b) {
			if (sem_wait(&ap->lock_b) == -1)
				err(1, "sem_wait");
			for (c = 0; c < COUNTER_LAST; c++)
				printf("%-20s: %lu\n", counter_names[c],
				    ap->c_b[c]);
			if (sem_post(&ap->lock_b) == -1)
				err(1, "sem_post");
		} else {
			if (sem_wait(&ap->lock_a) == -1)
				err(1, "sem_wait");
			for (c = 0; c < COUNTER_LAST; c++)
				printf("%-20s: %lu\n", counter_names[c],
				    ap->c_a[c]);
			if (sem_post(&ap->lock_a) == -1)
				err(1, "sem_post");
		}
	}
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

/*
 * We pass the counter being modified so we don't have to copy all of them.
 * current_arena->b was already seen by the reader before we lock so we
 * can flip it while holding the lock.
 */
static void
counters_flip(int c)
{
	if (current_arena->b) {
		if (sem_wait(&current_arena->lock_a) == -1)
			abort();
		current_arena->c_a[c] = current_arena->c_b[c];
		current_arena->b = 0;
	} else {
		if (sem_wait(&current_arena->lock_b) == -1)
			abort();
		current_arena->c_b[c] = current_arena->c_a[c];
		current_arena->b = 1;
	}
}

void
counters_add(int c, uint64_t v)
{
	if (sem_trywait((current_arena->b)
	    ? &current_arena->lock_b
	    : &current_arena->lock_a) == -1) {
		if (errno != EAGAIN)
			abort();
		counters_flip(c);
	}
	if (current_arena->b) {
		current_arena->c_b[c] += v;
		if (sem_post(&current_arena->lock_b) == -1)
			abort();
	} else {
		current_arena->c_a[c] += v;
		if (sem_post(&current_arena->lock_a) == -1)
			abort();
	}
}

void
counters_sub(int c, uint64_t v)
{
	if (sem_trywait((current_arena->b)
	    ? &current_arena->lock_b
	    : &current_arena->lock_a) == -1) {
		if (errno != EAGAIN)
			abort();
		counters_flip(c);
	}
	if (current_arena->b) {
		if (v >= current_arena->c_b[c])
			current_arena->c_b[c] = 0;
		else
			current_arena->c_b[c] -= v;
		if (sem_post(&current_arena->lock_b) == -1)
			abort();
	} else {
		if (v >= current_arena->c_a[c])
			current_arena->c_a[c] = 0;
		else
			current_arena->c_a[c] -= v;
		if (sem_post(&current_arena->lock_a) == -1)
			abort();
	}
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
