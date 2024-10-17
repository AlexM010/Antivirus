CC = gcc
CFLAGS = -pedantic -Wall -g 
SSLFLAGS = -l -lcurl -lcrypto -lssl 

all: antivirus

antivirus: ./build/antivirus.o
	$(CC) $(CFLAGS) $(SSLFLAGS) -o $@ $^ $(SSLFLAGS)
	
./build/%.o: ./src/%.c
	@mkdir -p build/
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -rf build antivirus

www.happylife.expert
www.roberthaveman.wixsite.com
www.miguelmgaspar.com
www.6apps.net
pub-f644c107c0aa4e55b7c24...
www.ukpropertysummit.com
www.vasisht5001.github.io