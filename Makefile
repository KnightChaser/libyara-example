CC = gcc
CFLAGS = -Wall $(shell pkg-config --cflags yara)
LDFLAGS = $(shell pkg-config --libs yara)

all: scan

scan: scan.c
	$(CC) $(CFLAGS) -o scan.out scan.c $(LDFLAGS)

clean: scan.out
	rm scan.out
