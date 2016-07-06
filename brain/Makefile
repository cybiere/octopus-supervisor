.PHONY: all clear mrproper install

CC = gcc
CFLAGS = -g -lpthread -lcrypto -lssl -Wall -Wextra -pedantic -lsqlite3 -lcrypt
EXEC = octoBrain

OBJECTS = webServ.o registerer.o maestro.o dbManager.o commander.o listener.o

all: $(EXEC)

$(EXEC) : main.o $(OBJECTS) fct.o
	$(CC) -o $@ $^ $(CFLAGS)

main.o : main.c headers/fct.h
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
	mkdir -p /etc/octopus/brain/
	mkdir -p /usr/share/octopus/brain/
	mv $(EXEC) /usr/bin/
	cp *.pem /etc/octopus/brain/
	cp -R web /usr/share/octopus/brain/
	cp brain.db /usr/share/octopus/brain/

