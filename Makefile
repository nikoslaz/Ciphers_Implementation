CC = gcc
CFLAGS = -Wall -Wextra -g
TARGET = cs457_crypto

OBJS = cs457_crypto.o main.o
HDRS = cs457_crypto.h 

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

cs457_crypto.o: cs457_crypto.c $(HDRS) 
	$(CC) $(CFLAGS) -c cs457_crypto.c

main.o: main.c $(HDRS) 
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJS) $(TARGET)