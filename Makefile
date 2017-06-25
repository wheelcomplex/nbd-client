PROG = nbd-client
SRCS = nbd-client.c ggate.c main.c
DEBUG_FLAGS = -g
CSTD = c11
CFLAGS = -O0 -pipe
LDADD += -lm -lpthread

DESTDIR = /usr/local
BINDIR = /sbin
MAN =

.include <bsd.prog.mk>
