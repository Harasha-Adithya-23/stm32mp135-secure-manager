CC ?= gcc

CFLAGS += -Wall
CFLAGS += -I../ta

LDLIBS += -lteec

BINARY = secure_manager_host

all: $(BINARY)

$(BINARY): main.o
	$(CC) -o $@ $^ $(LDLIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f *.o $(BINARY)
