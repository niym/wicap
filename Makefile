AKEFLAGS += --no-print-directory

PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
PKG_CONFIG ?= pkg-config

MKDIR ?= mkdir -p
INSTALL ?= install
CC ?= "gcc"

CFLAGS ?= -MMD -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common

LIBS += -lpcap

OBJS += ./radiotap.o
OBJS += ./wicap.o

-include $(OBJS:%.o=%.d)

all: wicap

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

wicap: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o wicap

.PHONY : clean
