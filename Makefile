CC = cc
CFLAGS = -Wall -Wno-format -g
LIBS = -lcrypto -lssl
SRCS = mdr.c mdrc.c mdr_tests.c
OBJS = mdr.o

all: depend mdrc mdr_tests

depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

mdr_tests: mdr_tests.c ${OBJS}
	${CC} ${CFLAGS} mdr_tests.c $(LIBS) ${OBJS} -o mdr_tests

mdrc: mdrc.c ${OBJS}
	${CC} ${CFLAGS} mdrc.c $(LIBS) ${OBJS} -o mdrc

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

clean:
	rm -f *.o mdr_tests mdrc *.core .depend
