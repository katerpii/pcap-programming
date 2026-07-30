LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c pcap-test.h
# 	gcc -o pcap-test pcap-test.c

clean:
	rm -f pcap-test *.o