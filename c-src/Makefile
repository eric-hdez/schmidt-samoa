CC = clang
CFLAGS = -g -Wall -Wextra -Werror -Wpedantic

all: keygen

keygen: keygen.o numtheory.o ssc.o randstate.o
	$(CC) $(CFLAGS) -lgmp -o keygen keygen.o numtheory.o ssc.o randstate.o

keygen.o: keygen.c
	$(CC) $(CFLAGS) -c keygen.c

numtheory.o: numtheory.c
	$(CC) $(CFLAGS) -c numtheory.c

ssc.o: ssc.c
	$(CC) $(CFLAGS) -c ssc.c

randstate.o: randstate.c
	$(CC) $(CFLAGS) -c randstate.c

clean:
	rm -f *.o keygen

format:
	clang-format -i -style=file *.[ch]
