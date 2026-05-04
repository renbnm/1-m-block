LDLIBS=-lnetfilter_queue

all: 1m-block

main.o: ip.h tcp.h main.cpp
ip.o: ip.h ip.cpp
tcp.o: tcp.h tcp.cpp

1m-block: main.o ip.o tcp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o
