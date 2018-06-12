CC     = gcc
TESTS := $(patsubst %.c,%,$(wildcard *.c))

all: $(TESTS)

clean:
	$(RM) $(TESTS)

% : %.c
	$(CC) -o $@ $< -lm
