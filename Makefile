CC = cc
CFLAGS = -Wall -Wno-format -g
LIBS = -lcrypto -lssl

SRCS = mdr.c mdrc.c mdr_mdrd.c mdr_tests.c config_vars.c idxheap.c tlsev.c \
	util.c xlog.c

MDRD_OBJS = config_vars.o idxheap.o mdr.o mdr_mdrd.o tlsev.o util.o xlog.o

all: .depend mdrc mdr_tests mdrd

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

mdr_tests: mdr_tests.c mdr.o
	${CC} ${CFLAGS} mdr_tests.c $(LIBS) mdr.o -o mdr_tests

mdrc: mdrc.c mdr.o
	${CC} ${CFLAGS} mdrc.c $(LIBS) mdr.o -o mdrc

mdrd: mdrd.c $(MDRD_OBJS)
	${CC} ${CFLAGS} mdrd.c $(LIBS) ${MDRD_OBJS} -o mdrd

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

clean:
	rm -f *.o mdr_tests mdrc mdrd *.core .depend
