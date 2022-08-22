LDLIBS=-lpcap

all: arp-spoofing


main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) -g $^ $(LOADLIBES) $(LDLIBS)  -o $@ -lpthread

clean:
	rm -f arp-spoofing *.o

