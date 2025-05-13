# Makefile for DES-based TCP Chat Program

CC = g++
CFLAGS = -Wall -g -std=c++11

TARGET = chat
SRCS = main.cpp tcp_socket.cpp des.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean