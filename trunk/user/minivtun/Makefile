
CFLAGS += -Wall
HEADERS = minivtun.h library.h list.h jhash.h

minivtun: minivtun.o library.o server.o client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto
	$(STRIP) $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

install: minivtun
	cp -f minivtun $(PREFIX)/sbin/

clean:
	rm -f minivtun *.o

romfs:
	$(ROMFSINST) /usr/sbin/minivtun
