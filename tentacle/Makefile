.PHONY: all clear mrproper install

CC = gcc
CFLAGS = -Wall -Wextra -pedantic -g -lssl -lcrypto -lpthread
EXEC = octoTentacle

OBJECTS = registerer.o commander.o

all: $(EXEC)

$(EXEC) : main.o fct.o  $(OBJECTS)
	$(CC) -o $@ $^ $(CFLAGS)

main.o : main.c
	$(CC) -c $^ $(CFLAGS)

fct.o : sources/fct.c headers/fct.h
	$(CC) -c $^ $(CFLAGS)

%.o : sources/%.c headers/%.h headers/fct.h
	$(CC) -c $^ $(CFLAGS)

clean:
	rm -rf *.o headers/*.h.gch

mrproper: clean
	rm -rf $(EXEC)

install:
	mkdir -p /etc/octopus/tentacle
	cp cert.pem key.pem /etc/octopus/tentacle
	mkdir -p /usr/share/octopus/tentacle
	mkdir -p /usr/share/octopus/tentacle/scripts
	mkdir -p /usr/share/octopus/tentacle/results
	mv $(EXEC) /usr/sbin/
