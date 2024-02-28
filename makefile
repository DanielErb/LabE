all: myELF



myELF: myELF.o
	gcc -g -Wall -m32 -o myELF myELF.o

myELF.o: myELF.c
	gcc -g -Wall -m32 -c -o myELF.o myELF.c


.PHONY: clean

clean:
	rm -f *.o myELF