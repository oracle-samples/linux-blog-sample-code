all: entry-fuzz initrd.entry-fuzz.gz

clean:
	rm -rf entry-fuzz initrd/ initrd.entry-fuzz.gz

entry-fuzz: main.cc
	g++ -std=c++14 -Wall -O2 -static -o $@ $<

initrd.entry-fuzz.gz: entry-fuzz
	rm -rf initrd/
	mkdir initrd/
	cp entry-fuzz initrd/init
	(cd initrd/ && (find | cpio -o -H newc)) | gzip -c > $@
