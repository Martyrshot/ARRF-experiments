HASHMAPDIR=c-hashmap/
SOURCEDIR=src/
TESTINCLUDES=-Iinclude/
INCLUDES=$(TESTINCLUDES) -I$(HASHMAPDIR)
TESTDIR=tests/
SOURCES=$(SOURCEDIR)resource_record.c $(SOURCEDIR)question.c $(SOURCEDIR)rrfrag.c \
	$(SOURCEDIR)packedrr.c $(SOURCEDIR)dns_message.c $(HASHMAPDIR)map.c
TESTSOURCES=$(SOURCES)
.PHONY: all

all: tests

tests: resource_record_tests # netfilterqueue_tests

daemon: $(SOURCEDIR)daemon.c $(HASHMAPDIR)map.c $(SOURCES)
	$(CC) -o $@ -Wall -pedantic -g $^ -lnetfilter_queue -lrt -lm $(INCLUDES) -pthread 

resource_record_tests: $(TESTSOURCES) $(TESTDIR)resource_record_test.c
	$(CC) -o $(TESTDIR)$@ -Wall -pedantic -fsanitize=address -g $(TESTINCLUDES) $^

netfilterqueue_tests: $(TESTDIR)netqueue_testing.c
	$(CC) -o $(TESTDIR)$@ -Wall -pedantic $^ -lnetfilter_queue -lrt -lm


responder: $(TESTDIR)responder.c $(TESTSOURCES)
	$(CC) -o $(TESTDIR)$@ -Wall -pedantic $^ $(INCLUDES)

requester: $(TESTDIR)requester.c $(TESTSOURCES)
	$(CC) -o $(TESTDIR)$@ -Wall -pedantic $^ $(INCLUDES)
