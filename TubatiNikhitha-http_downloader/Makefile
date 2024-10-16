

#compiler
CC = gcc

#Compiler flags
CFLAGS = -Wall -Wextra

#Libraries
LIBS = -lssl -lcrypto

#Source file
SRC = http_downloader.c

#Output executable
OUT = http_downloader

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OUT)
	rm -f *.gif
	rm -f part_*
	rm -f range_*	
