all: PageMap32 PageMap64

PageMap32: PageMap32.o
	g++ -m32 -Wall -Wextra $^ -o $@

PageMap64: PageMap64.o
	g++ -m64 -Wall -Wextra $^ -o $@
	
%32.o: %.c
	g++ -c $^ -m32 -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@

%64.o: %.c
	g++ -c $^ -m64 -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@
	
clean:
	rm -f *.o *.so *~ core.* PageMap32 PageMap64

install32: PageMap32
	sudo /bin/sh -c "cp PageMap32 /usr/local/bin && chmod 755 /usr/local/bin/PageMap32"

install64: PageMap64
	sudo /bin/sh -c "cp PageMap64 /usr/local/bin && chmod 755 /usr/local/bin/PageMap64"

install: install32 install64
	
