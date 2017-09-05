CC = gcc
LIBS = -lnetfilter_queue
INCLUDES =
CFLAGS = -O2 -g -Wall -std=gnu99 -c $(INCLUDES)
OFLAGS = -O2 -g -Wall -std=gnu99 $(LIBS)

SRCDIR = .
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(addsuffix .o, $(basename $(SRCS)))

APP = xor

all:$(APP)  ## build target binary file(default).

$(APP):$(OBJS)
	$(CC) $(OFLAGS) -o $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -o $@ $<

clean: ## clean intermediate and target binary files.
	rm -f *.o $(APP)

init: ## install dep.
	yum install libnetfilter_queue libnetfilter_queue-devel
.PHONY: help
help: ## Show this help message.
	@echo 'usage: make [target] ...'
	@echo
	@echo 'targets:'
	@egrep '^(.+)\:.+##\ (.+)' ${MAKEFILE_LIST} | sed 's/:.*##/:#/' | column -t -c 2 -s ':#'
