CC=gcc
STRIP=strip
CFLAGS=-O2 -Wall
LDFLAGS=
LIBS=

all: lv0tool


lv0tool: main.o crypt.o tables.o util.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@
	$(STRIP) -s $@

crypt.o: crypt.c
	$(CC) $(CFLAGS) -DCRYPTO_PPU -c $< -o $@

tables.o: tables.c
	$(CC) $(CFLAGS) -DCRYPTO_PPU -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lv0tool
