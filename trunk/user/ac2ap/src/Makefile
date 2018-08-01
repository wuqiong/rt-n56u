#
#


CC ?= gcc
CFLAGS += -Wall
HEADERS =


%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

all: ac2ap.o
	$(CC) $(LDFLAGS) -o ac2ap $^

clean:
	rm -f ac2ap *.o

