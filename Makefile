CC = cc
CFLAGS = -Wall -g

# pthread for semaphores
LIBS = -lcrypto -lssl -pthread

SRCS = mdr.c mdrc.c mdr_mdrd.c mdr_tests.c flatconf.c idxheap.c tlsev.c \
	util.c xlog.c

MDRD_OBJS = flatconf.o idxheap.o mdr.o mdr_mdrd.o tlsev.o util.o xlog.o
MDRD_ECHO_OBJS = mdr.o mdr_mdrd.o xlog.o
YACC=yacc

all: .depend mdrc mdr_tests mdrd mdrd_backend_echo

.depend: ${SRCS}
	mkdep ${CFLAGS} ${SRCS}

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $<

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

mdr_tests: mdr_tests.c mdr.o util.o xlog.o
	${CC} ${CFLAGS} mdr_tests.c $(LIBS) mdr.o util.o xlog.o -o mdr_tests

mdrc: mdrc.c mdr.o mdr_mdrd.o
	${CC} ${CFLAGS} mdrc.c $(LIBS) mdr.o -o mdrc

mdrd: mdrd.c $(MDRD_OBJS)
	${CC} ${CFLAGS} mdrd.c $(LIBS) ${MDRD_OBJS} -o mdrd

mdrd_backend_echo: mdrd_backend_echo.c mdr.o mdr_mdrd.o xlog.o
	${CC} ${CFLAGS} mdrd_backend_echo.c $(LIBS) ${MDRD_ECHO_OBJS} -o mdrd_backend_echo

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

install: all
	install -o root -g wheel -m 0555 mdrd_backend_echo /usr/local/bin/
	install -o root -g wheel -m 0555 mdrd /usr/local/bin/

clean:
	rm -f *.o mdr_tests mdrc mdrd mdrd_backend_echo flatconf.c *.core .depend
