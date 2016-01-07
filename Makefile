CC=clang
CFLAGS=-c -Wall -std=gnu11

all: dns_client

dns_client: main.o dns.o
	$(CC) main.o dns.o -o bin/dns_client

main.o: main.c
	$(CC) $(CFLAGS) main.c

dns.o: dns.c
	$(CC) $(CFLAGS) dns.c

clean:
	rm *.o bin/dns_client
