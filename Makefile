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

.if defined(LIBCASPER) && defined(LIBCAP_DNS)
CFLAGS += -DHAVE_LIBCASPER
LDADD += -lcasper -lcap_dns -lnv
.endif
