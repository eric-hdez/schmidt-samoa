CC = clang
CFLAGS = -g -Wall -Wextra -Werror -Wpedantic

all: main

main: main.o numtheory.o ssc.o randstate.o
	$(CC) $(CFLAGS) -lgmp -o main main.o numtheory.o ssc.o randstate.o

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

numtheory.o: numtheory.c
	$(CC) $(CFLAGS) -c numtheory.c

ssc.o: ssc.c
	$(CC) $(CFLAGS) -c ssc.c

randstate.o: randstate.c
	$(CC) $(CFLAGS) -c randstate.c

clean:
	rm -f *.o main

format:
	clang-format -i -style=file *.[ch]
