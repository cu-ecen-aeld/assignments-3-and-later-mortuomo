FILENAME = aesdsocket
CFLAGS ?= -Wall -Werror -g

.PHONY: all default clean

default: $(FILENAME).c $(FILENAME).h
	$(CC) $(CFLAGS) $(INCLUDES) $(FILENAME).c -o $(FILENAME) $(LDFLAGS)

all: clean default

clean:
	rm -rf *.o $(FILENAME)