# Makefile for dnsproxy

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
version := $(shell sh -c 'cat VERSION')

RM = rm -f
CP = cp -f

CFLAGS = -O2 -Wall -DVERSION=\"${version}\" -DNDEBUG
LDFLAGS = -s

EXEC = dnsproxy
INCLUDES = $(wildcard *.h embed/*.h)
SOURCES = $(wildcard *.c embed/*.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))


all: $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(SOURCES) $(INCLUDES)

$(EXEC): $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LDFLAGS)

clean:
	$(RM) *.o embed/*.o *~ $(EXEC)

romfs:
	$(ROMFSINST) /usr/bin/$(EXEC)
	$(ROMFSINST) /usr/bin/dnsproxy.sh

