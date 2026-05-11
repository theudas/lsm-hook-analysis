CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

.PHONY: all clean

all: lha-eventd

lha-eventd: lha-eventd.c
	$(CC) $(CFLAGS) -I../include/uapi -o $@ $<

clean:
	rm -f lha-eventd
