PROG = nbd-client
SRCS = nbd-client.c ggate.c main.c
DEBUG_FLAGS = -g
CSTD = c11
CFLAGS = -O0 -pipe -fblocks
LDADD += -lm -lpthread -lBlocksRuntime

DESTDIR = /usr/local
BINDIR = /sbin
MAN =

.include <bsd.prog.mk>
