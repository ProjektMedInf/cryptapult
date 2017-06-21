CC=gcc
CFLAGS=-lsodium
CROSSC=arm-none-eabi-gcc
CROSSFLAGS=-I../libsodium/include --specs=nosys.specs

main: main.c
	$(CC) -ggdb -o main $(CFLAGS) main.c

crosscompile: main.c
	$(CROSSC) -ggdb -o main $(CROSSFLAGS) main.c ../libsodium/lib/libsodium.a
