#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#define __STDC_LIMIT_MACROS
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

struct sstats{
	uint64_t size;
	uint64_t present;
	uint64_t priv;
	uint64_t anon;
	uint64_t swapped;
};

void usage();
void printsize(uint64_t size);
void dumpflags(uint64_t flags);
void flushnp(uint64_t *npstart, uint64_t offset, bool verbose, bool skip);
int dumppid(unsigned long pid, bool summary, bool verbose, bool map, bool writable);
void dumpstats(struct sstats *stats, bool title);
void clearstats(struct sstats *stats);

int main(int argc, char **argv)
{
	int opt;
	bool verbose = false;
	bool summary = false;
	bool map = false;
	bool writable = false;
	char *end;
	unsigned long pid;

	while((opt = getopt(argc, argv, "vmsw")) != -1){
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'm':
			map = true;
			break;
		case 's':
			summary = true;
			break;
		case 'w':
			writable = true;
			break;
		default:
			usage(); 
			return 1;
		}
	}

	if(verbose && map) return 4;

	if(optind != argc-1){
		usage();
		return 2;
	}
	
	// Get pid
	pid = strtoul(*(argv+optind), &end, 10);
	if(errno != 0 || *end != '\x0'){
		usage();
		return 3;
	}
	
	return dumppid(pid, summary, verbose, map, writable);
}

int dumppid(unsigned long pid, bool summary, bool verbose, bool map, bool writable)
{
	int result = 0;
	
	bool skip;
	char *end;
	char path[PATH_MAX+1];
	FILE *hmaps;
	char *line;
	size_t linesize;
	int linelen;
	uint64_t range[2];
	const char *item;
	char *perms;

	int hpagemap;
	int b;
	uint64_t entry;
	uint64_t npstart;
	uint64_t offset;
	uint64_t pfn;
	uint64_t swapfile;
	uint64_t swapoff;
	int present,swapped;
	unsigned int shift;
	unsigned int pagesize;

	int hkpagecount;
	uint64_t pagecnt;
	int hkpageflags;
	uint64_t pageflags;
	
	struct sstats stats;

	do{	
		// Open page mapping
		sprintf(path, "/proc/%lu/pagemap", pid);
		hpagemap = open(path, O_RDONLY);
		if(hpagemap == -1){
			printf("Error opening %s\n", path);
			result = 10;
			break;
		}

		// Open maps
		sprintf(path, "/proc/%lu/maps", pid);
		hmaps = fopen(path, "r");
		if(hmaps == NULL){
			printf("Error opening %s\n", path);
			result = 11;
			break;
		}

		// Try and open kernel page stats
		hkpagecount = open("/proc/kpagecount", O_RDONLY);
		hkpageflags = open("/proc/kpageflags", O_RDONLY);

		// Clear stats
		clearstats(&stats);

		line=NULL;
		linesize=0;
		while(1){
			if(getline(&line, &linesize, hmaps) == -1) break;
			linelen = strlen(line);

			// Convert 0x0a to null
			line[--linelen] = '\x0';
			if(linelen > 74) item = line + 73;
			else item = "[Anonymous]";

			// Get range start
			range[0] = strtoull(line, &end, 16);
			if(errno != 0) continue;

			// Get range end
			++end;
			range[1] = strtoull(end, &end, 16);
			if(errno != 0) continue;

			// Get perms
			perms = ++end;
			end = strchr(perms, ' ');
			*end = '\x0';

			if(writable && strchr(perms, 'w')==NULL) skip = true;
			else skip = false;

			if((verbose || summary || map) && !skip){
				// Print section header
				printf("==================== %s [%s] ", item, perms);
				printsize(range[1]-range[0]);
				printf(" ====================\n");	
			}
			stats.size += range[1]-range[0];
			
			lseek(hpagemap, (range[0]/4096)*sizeof(uint64_t), SEEK_SET);
			offset = range[0];
			npstart = UINT64_MAX;
			while(offset<range[1]){
				b = read(hpagemap, &entry, sizeof(uint64_t));
				if(b <= 0) break;

				// Unpack common bits
				present = (entry & 0x8000000000000000) >> 62;
				swapped = (entry & 0x4000000000000000) >> 61;
				shift = (entry & 0x1f80000000000000) >> 55;
				pagesize = (1<<shift);
				
				if(!present && !swapped){
					// Page not present in physical ram or swap
					if(shift==0) pagesize = 4096;
					if(npstart == UINT64_MAX) npstart = offset;
					if(map && !skip) printf(".");
				}
				else{
					// Page is in physical ram or swap
					flushnp(&npstart, offset, verbose, skip);

					if(verbose && !skip){
						// Print page range
						printf("   %016lx-%016lx ", offset, offset+pagesize-1);
						printsize(pagesize);
					}
					if(present){
						// Page is present in RAM
						stats.present += pagesize;
						
						// Get PFN
						pfn = entry & 0x07fffffffffffff;
						if(verbose && !skip){
							printf(", Present (pfn %016lx)", pfn);
						}
						if(map && !skip) printf("P");
						if(hkpagecount >= 0){
							// Get page reference count if we can
							lseek(hkpagecount, pfn*sizeof(uint64_t), SEEK_SET);						
							b = read(hkpagecount, &pagecnt, sizeof(uint64_t));
							if(b == sizeof(uint64_t)){
								if(verbose && !skip){
									printf(", RefCnt %lu", pagecnt);
								}
								if(pagecnt <= 1) stats.priv += pagesize;
							}
						}
						if(hkpageflags >= 0){
							// Get page flags if we can
							lseek(hkpageflags, pfn*sizeof(uint64_t), SEEK_SET);						
							b = read(hkpageflags, &pageflags, sizeof(uint64_t));
							if(b == sizeof(uint64_t)){
								if(verbose && !skip){
									printf(", Flags ");
									dumpflags(pageflags);
								}
								if(pageflags & (1<<12)) stats.anon += pagesize;
							}
						}
					}
					if(swapped){
						// Page is in swap space
						if(!present){
							stats.swapped += pagesize;
							if(map && !skip) printf("S");
						}
						swapfile = entry & 0x000000000000001f;
						swapoff = (entry & 0x07fffffffffffe0) >> 5;
						if(verbose && !skip){
							printf(", Swapped (seg %u offs %016lx)", (unsigned int) swapfile, swapoff);
						}
					}
					
					if(verbose && !skip){
						printf("\n");
					}
				}
				
				// Move to next page
				offset+=pagesize;
			}
			flushnp(&npstart, offset, verbose, skip);

			if(map && !skip) printf("\n");			
			if(summary){
				if(skip) clearstats(&stats);
				else dumpstats(&stats, false);
			}
		}	

		if(!summary && !map){
			dumpstats(&stats, verbose);
		}
	} while(0);
	
	return result;
}

void dumpstats(struct sstats *stats, bool title)
{
	if(title){
		printf("============ Stats ============\n");
	}
	printf("Size:      %8lu kB\n", stats->size / 1024);
	printf("Present:   %8lu kB (%.1f%%)\n", stats->present / 1024, ((double)stats->present/(double)stats->size)*100.0);
	if(stats->priv){
	printf("  Unique:  %8lu kB (%.1f%%)\n", stats->priv / 1024, ((double)stats->priv/(double)stats->present)*100.0);
	}
	if(stats->anon){
	printf("  Anon:    %8lu kB (%.1f%%)\n", stats->anon / 1024, ((double)stats->anon/(double)stats->present)*100.0);
	}
	printf("Swapped:   %8lu kB (%.1f%%)\n", stats->swapped / 1024, ((double)stats->swapped/(double)stats->size)*100.0);	
	
	clearstats(stats);
}

void clearstats(struct sstats *stats)
{
	stats->size = 0;
	stats->present = 0;
	stats->priv = 0;
	stats->anon = 0;
	stats->swapped = 0;
}

void usage()
{
	printf("Usage: PageMap [-v | -m] [-s] [-w] <pid>\n"
	       "   where: -v  Dump each present / swapped page entry\n"
	       "          -m  Dump status map of each mapped segment ('P'resent, 'S'wapped or '.' for not present)\n"
	       "          -s  Print statistics for each mapped section\n"
	       "          -w  Only process writable sections\n");
}

void printsize(uint64_t size)
{
	int mult = 0;
	const char *unit;
	
	while(size > (mult == 0 ? 1024 : 8192)){
		size /= 1024;
		++mult;	
	}
	switch(mult){
	case 0:
		unit="B";
		break;
	case 1:
		unit="kB";
		break;
	case 2:
		unit="MB";
		break;
	case 3:
		unit="GB";
		break;
	case 4:
		unit="TB";
		break;
	case 5:
		unit="PB";
		break;
	case 6:
		unit="EB";
		break;
	default:
		unit="??";
		break;
	}
	
	printf("[%4lu%2s]",size,unit);
}

void dumpflags(uint64_t flags)
{
	int loop;
	int first=1;
	
	for(loop=0; loop<64; loop++){
		if(flags & 1){
			if(first){
				printf("[");
				first=0;
			}
			else{
				printf(" ");
			}
			
			switch(loop){
			case 0:
				printf("LOCKED");
				break;
			case 1:
				printf("ERROR");
				break;
			case 2:
				printf("REFERENCED");
				break;
			case 3:
				printf("UPTODATE");
				break;
			case 4:
				printf("DIRTY");
				break;
			case 5:
				printf("LRU");
				break;
			case 6:
				printf("ACTIVE");
				break;
			case 7:
				printf("SLAB");
				break;
			case 8:
				printf("WRITEBACK");
				break;
			case 9:
				printf("RECLAIM");
				break;
			case 10:
				printf("BUDDY");
				break;
			case 11:
				printf("MMAP");
				break;
			case 12:
				printf("ANON");
				break;
			case 13:
				printf("SWAPCACHE");
				break;
			case 14:
				printf("SWAPBACKED");
				break;
			case 15:
				printf("COMPHEAD");
				break;
			case 16:
				printf("COMPTAIL");
				break;
			case 17:
				printf("HUGE");
				break;
			case 18:
				printf("UNEVICTABLE");
				break;
			case 19:
				printf("HWPOISON");
				break;
			case 20:
				printf("NOPAGE");
				break;
			case 21:
				printf("KSM");
				break;
			default:
				printf("<%d>",loop);
				break;
			}
		}
		flags >>= 1;
	}
	if(first) printf("[]");
	else printf("]");
}

void flushnp(uint64_t *npstart, uint64_t offset, bool verbose, bool skip)
{
	if(*npstart != UINT64_MAX){
		if(verbose && !skip){
			printf("   %016lx-%016lx ", *npstart, offset-1);
			printsize(offset-*npstart);
			printf(", Not present\n");
		}
		*npstart = UINT64_MAX;
	}
}


