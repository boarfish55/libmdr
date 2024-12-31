#ifndef COUNTERS_H
#define COUNTERS_H

#include <semaphore.h>
#include <stdint.h>

enum {
	COUNTER_RESTARTS = 0,
	COUNTER_TOTAL_CLIENTS,
	COUNTER_ACTIVE_CLIENTS,
	COUNTER_READ_PAUSES,
	COUNTER_WAKE_FOR_ACCEPT,
	COUNTER_LAST
};

struct counter {
	uint64_t v;
	sem_t    lock;
};

struct counters_arena {
	pid_t          pid;
	struct counter c[COUNTER_LAST];
};

int      counters_init(int);
void     counters_read(const char *);
uint64_t counters_get(int);
void     counters_add(int, uint64_t);
void     counters_sub(int, uint64_t);
void     counters_incr(int);
void     counters_decr(int);
int      counters_arena_count();
int      counters_set_arena(int);
void     counters_set_pid(pid_t);
int      counters_find_arena(pid_t);

#endif
