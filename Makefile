all: PageMap32 PageMap64

PageMap32: PageMap32.o
	g++ -m32 -Wall -Wextra $^ -o $@

PageMap64: PageMap64.o
	g++ -m64 -Wall -Wextra $^ -o $@
	
%32.o: %.c
	g++ -c $^ -m32 -Wall -Wextra -fPIC -fno-inline -g -o $@

%64.o: %.c
	g++ -c $^ -m64 -Wall -Wextra -fPIC -fno-inline -g -o $@
	
clean:
	rm -f *.o *.so *~ core.* PageMap32 PageMap64
	
