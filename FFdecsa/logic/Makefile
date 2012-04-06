all: logic

logic: logic.o
	gcc -o logic logic.o

logic.o: logic.c
	gcc -O3 -march=athlon-xp -c logic.c

clean:
	rm logic *.o
