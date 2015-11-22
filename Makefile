CC=clang
CFLAGS=-c -Wall

all: dns_client

dns_client: main.o
	$(CC) main.o -o dns_client

main.o: main.c
	$(CC) $(CFLAGS) main.c

clean:
	rm *o dns_client
