LDLIBS=-lpcap

all: airodump-ng

main.o: main.cpp

radiotap.o: radiotap.h radiotap.cpp

airodump-ng: main.o radiotap.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump-ng *.o