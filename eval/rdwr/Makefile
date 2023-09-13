all: twrite rdwr_data

twrite: twrite.c
	gcc -o twrite -O2 twrite.c

rdwr_data: rdwr_data.tgz
	tar xzf rdwr_data.tgz
	touch rdwr_data

clean:
	rm -rf rdwr_data
	rm -f *.o twrite
