# Native binary by default
default: PageMap

# All binary flavours
all: PageMap PageMap32 PageMapx32 PageMap64

# Native PageMap binary
PageMap: PageMap.o
	g++ -Wall -Wextra $^ -o $@

# 32-bit PageMap binary
PageMap32: PageMap32.o
	g++ -m32 -Wall -Wextra $^ -o $@

# 64-bit code, 32-bit pointer PageMap binary
PageMapx32: PageMapx32.o
	g++ -mx32 -Wall -Wextra $^ -o $@

# 64-bit PageMap binary
PageMap64: PageMap64.o
	g++ -m64 -Wall -Wextra $^ -o $@

# x32 compile
%x32.o: %.c
	g++ -c $^ -mx32 -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@

# 32-bit compile
%32.o: %.c
	g++ -c $^ -m32 -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@

# 64-bit compile
%64.o: %.c
	g++ -c $^ -m64 -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@

# Native compile
%.o: %.c
	g++ -c $^ -Wall -Wextra -fPIC -fno-inline -g -O2 -o $@

# Clean backup, cores and binaries
clean:
	rm -f *.o *~ core.* PageMap PageMap32 PageMap64 PageMapx32

# Native install
install: PageMap
	sudo /bin/sh -c "cp PageMap /usr/local/bin && chmod 755 /usr/local/bin/PageMap"

# 32-bit install
install32: PageMap32
	sudo /bin/sh -c "cp PageMap32 /usr/local/bin && chmod 755 /usr/local/bin/PageMap32"

# x32 install
installx32: PageMapx32
	sudo /bin/sh -c "cp PageMapx32 /usr/local/bin && chmod 755 /usr/local/bin/PageMapx32"

# 64-bit install
install64: PageMap64
	sudo /bin/sh -c "cp PageMap64 /usr/local/bin && chmod 755 /usr/local/bin/PageMap64"
