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

struct counters_arena {
	pid_t    pid;
	int      b;
	sem_t    lock_a;
	uint64_t c_a[COUNTER_LAST];
	sem_t    lock_b;
	uint64_t c_b[COUNTER_LAST];
};

int  counters_init(const char *, int);
void counters_read(const char *);
void counters_add(int, uint64_t);
void counters_sub(int, uint64_t);
void counters_incr(int);
void counters_decr(int);
int  counters_set_arena(int);
void counters_set_pid(pid_t);
int  counters_find_arena(pid_t);

#endif
