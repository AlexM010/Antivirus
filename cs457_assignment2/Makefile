CC = gcc
CFLAGS = -pedantic -Wall -g
SSLFLAGS = -lcrypto -lssl -g -lcurl
LIB = -I/home/misc/courses/hy457/libcurl/lib/include -L/home/misc/courses/hy457/libcurl/lib/lib

all: antivirus ransom
antivirus: ./build/antivirus.o
	$(CC) $(CFLAGS) $(LIB) -o $@ $^ $(SSLFLAGS)
ransom: ./build/ransomware.o
	$(CC) $(CFLAGS) -o $@ $^
./build/antivirus.o: ./src/antivirus.c
	@mkdir -p build/
	$(CC) $(CFLAGS) $(LIB) -c $< -o $@
./build/ransomware.o: ./test/ransomware.c
	@mkdir -p build/
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -rf build antivirus ransom
