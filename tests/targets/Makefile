CC     = gcc
CPP    = g++
TESTS := $(patsubst %.c,%,$(wildcard *.c)) $(patsubst %.cpp,%,$(wildcard *.cpp))

all: $(TESTS)

clean:
	$(RM) $(TESTS)

% : %.c
	$(CC) -o $@ $< -lm

% : %.cpp
	$(CPP) -o $@ $< -lQuantLib
