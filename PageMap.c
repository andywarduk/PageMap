#define __STDC_LIMIT_MACROS
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <termios.h>
#include <sys/ioctl.h>

struct global{
	int hkpagecount;
	int hkpageflags;
	
	bool terminal;
	int termwidth;
	int termheight;

	bool verbose;
	bool summary;
	bool map;
	bool writable;
	bool list;
	uint64_t pid;
};

struct sstats{
	uint64_t size;
	uint64_t present;
	uint64_t priv;
	uint64_t privavg;
	uint64_t anon;
	uint64_t refd;
	uint64_t swapped;
	uint64_t huge;
};

int initialise(struct global *globals);
void cleanup(struct global *globals);
void usage();
void printsize(uint64_t size);
void dumpflags(uint64_t flags);
void flushnp(struct global *globals, uint64_t *npstart, uint64_t offset, bool skip);
int dumppid(struct global *globals);
int dumpall(struct global *globals);
void dumpstats(struct global *globals, struct sstats *stats);
void clearstats(struct sstats *stats);
void printcmdline(uint64_t pid, int width);

int main(int argc, char **argv)
{
	int opt;
	struct global globals;
	char *end;
	int result = 0;

	initialise(&globals);

	// Parse arguments
	while ((opt = getopt(argc, argv, "vmswp:")) != -1){
		switch (opt) {
		case 'v':
			globals.verbose = true;
			break;

		case 'm':
			globals.map = true;
			break;

		case 's':
			globals.summary = true;
			break;

		case 'w':
			globals.writable = true;
			break;

		case 'p':
			if (globals.pid != 0) {
				usage();
				return 5;
			}

			if (strcmp(optarg, "self") == 0) {
				globals.pid = getpid();
			} else {
				// Get pid
				errno = 0;
				globals.pid = strtoull(optarg, &end, 10);
				if(errno != 0 || *end != '\x0'){
					usage();
					return 3;
				}
			}

			break;

		default:
			usage(); 
			return 1;

		}
	}

	if (optind != argc){
		usage();
		return 2;
	}

	if (globals.pid != 0) {
		if (globals.verbose && globals.map) return 4;
	} else{
		if (globals.verbose || globals.map || globals.summary || globals.writable) {
			usage();
			return 6;
		}
	}
	
	if (globals.pid)
		result = dumppid(&globals);
	else
		result = dumpall(&globals);

	cleanup(&globals);
	
	return result;
}

int initialise(struct global *globals)
{
	int result = 0;
	struct winsize window_size;

	globals->verbose = false;
	globals->summary = false;
	globals->map = false;
	globals->writable = false;
	globals->list = false;
	globals->pid = 0;
	
	// Try and open kernel page stats
	globals->hkpagecount = open("/proc/kpagecount", O_RDONLY);
	globals->hkpageflags = open("/proc/kpageflags", O_RDONLY);

	// Get terminal dimensions
	if (ioctl(fileno(stdin), TIOCGWINSZ, &window_size) == 0){
		globals->terminal = true;
		globals->termwidth = (int) window_size.ws_col;
		globals->termheight = (int) window_size.ws_row;
	} else{
		globals->terminal = false;
		globals->termwidth = 0;
		globals->termheight = 0;
	}
	
	return result;
}

void cleanup(struct global *globals)
{
	if (globals->hkpagecount >= 0) close(globals->hkpagecount);
	if (globals->hkpageflags >= 0) close(globals->hkpageflags);
}

int dumpall_filter(const struct dirent *entry)
{
	int result = 1;
	const char *ch;
	
	if (entry->d_type != DT_DIR) {
		result = 0;
	} else{
		result = 0;
		for (ch = entry->d_name; *ch != '\x0'; ch++) {
			if(isdigit(*ch)) result = 1;
			else {
				result = 0;
				break;
			}
		}
	}
	
	return result;
}

int dumpall_cmp(const struct dirent **one, const struct dirent **two)
{
	uint64_t pidone;
	uint64_t pidtwo;
	
	pidone = strtoull((*one)->d_name, NULL, 10);
	pidtwo = strtoull((*two)->d_name, NULL, 10);
	
	if (pidone < pidtwo) return -1;
	if (pidone == pidtwo) return 0;
	
	return 1;
}

int dumpall(struct global *globals)
{
	int result;
	struct dirent **entries;
	int nent;
	int loop;
	bool needhdg = true;
	int printed = 0;
	int statwidth;
	int procwidth;
	
	statwidth = 10 + (2 * (1 + 8));
	if (globals->hkpagecount >= 0) statwidth += 2 * (1 + 8);
	if (globals->hkpageflags >= 0) statwidth += 3 * (1 + 8);
	statwidth += 1 + 8 + 1;
	
	if(globals->terminal) {
		procwidth = globals->termwidth - statwidth;
		if (procwidth < 10) procwidth = 0;
	} else {
		procwidth = 0;
	}
	
	globals->list = true;
	do{
		nent = scandir("/proc", &entries, dumpall_filter, dumpall_cmp);
		if (nent < 0) {
			fprintf(stderr, "Error scanning /proc: ");
			perror(NULL);
			result = 20;
			break;	
		}

		for (loop = 0; loop < nent; loop++) {
			if (needhdg) {
				printf("====== PID     Size  Present");

				if (globals->hkpagecount >= 0) {
					printf("  Private  Average");
				}

				if (globals->hkpageflags >= 0) {
					printf("     Anon    Ref'd     Huge");
				}

				printf("  Swapped Process ======\n");
				needhdg = false;
			}

			globals->pid = strtoull(entries[loop]->d_name, NULL, 10);

			if (globals->pid > 0 && dumppid(globals) == 0) {
				printf(" ");
				printcmdline(globals->pid, procwidth);
				printf("\n");
				if (globals->terminal && globals->termheight > 2 && ++printed % (globals->termheight - 1) == 0) needhdg = true;
			}

			free(entries[loop]);
		}

		free(entries);
	} while(0);
	
	return result;
}

int dumppid(struct global *globals)
{
	int result = 0;
	
	bool skip;
	char *end;
	char path[PATH_MAX+1];
	FILE *hmaps = NULL;
	char *line;
	size_t linesize;
	int linelen;
	uint64_t range[2];
	uint64_t size;
	const char *item;
	char *perms;

	int hpagemap = 0;
	int b;
	uint64_t entry;
	uint64_t npstart;
	uint64_t offset;
	uint64_t pfn;
	uint64_t swapfile;
	uint64_t swapoff;
	int present, swapped;
	unsigned int pagesize = getpagesize();

	uint64_t pagecnt;
	uint64_t pageflags;
	
	struct sstats stats;

	bool gotpagecnt;
	bool gotpageflags;

	bool incompound = false;
	bool hdgotpagecnt = false;
	uint64_t hdpagecnt = 0;
	uint64_t hdpageflags = 0;

	do{	
		// Open page mapping
		sprintf(path, "/proc/%" PRIu64 "/pagemap", globals->pid);
		hpagemap = open(path, O_RDONLY);
		if (hpagemap == -1) {
			if(!globals->list || errno != EACCES){
				fprintf(stderr, "Error opening %s: ", path);
				perror(NULL);
			}
			result = 10;
			break;
		}

		// Open maps
		sprintf(path, "/proc/%" PRIu64 "/maps", globals->pid);
		hmaps = fopen(path, "r");
		if (hmaps == NULL) {
			if(!globals->list){
				fprintf(stderr, "Error opening %s: ", path);
				perror(NULL);
			}
			result = 11;
			break;
		}

		// Clear stats
		clearstats(&stats);

		if(globals->list){
			printf("%10" PRIu64, globals->pid);
		}

		line = NULL;
		linesize = 0;
		while (1){
			if (getline(&line, &linesize, hmaps) == -1) break;
			linelen = strlen(line);

			// Convert 0x0a to null
			line[--linelen] = '\x0';
			if (linelen > 74) item = line + 73;
			else item = "[Anonymous]";

			// Get range start
			errno = 0;
			range[0] = strtoull(line, &end, 16);
			if (errno != 0) continue;

			// Get range end
			++end;
			errno = 0;
			range[1] = strtoull(end, &end, 16);
			if (errno != 0) continue;

			// Calculate size
			size = range[1] - range[0];

			// Get perms
			perms = ++end;
			end = strchr(perms, ' ');
			*end = '\x0';

			if (globals->writable && strchr(perms, 'w') == NULL) skip = true;
			else skip = false;

			if ((globals->verbose || globals->summary || globals->map) && !skip) {
				// Print section header
				printf("==================== %s [%s] ", item, perms);
				printsize(size);
				printf(" ====================\n");	
			}
			stats.size += size;

			lseek64(hpagemap, (range[0] / pagesize) * sizeof(uint64_t), SEEK_SET);
			offset = range[0];
			npstart = UINT64_MAX;
			while (offset < range[1]){
				b = read(hpagemap, &entry, sizeof(uint64_t));
				if (b <= 0) break;

				// Unpack common bits
				present = (entry & 0x8000000000000000LL) >> 62;
				swapped = (entry & 0x4000000000000000LL) >> 61;
				
				if (!present && !swapped) {
					// Page not present in physical ram or swap
					if(npstart == UINT64_MAX) npstart = offset;
					if(globals->map && !skip) printf(".");

				} else {
					// Page is in physical ram or swap
					flushnp(globals, &npstart, offset, skip);

					if (globals->verbose && !skip) {
						// Print page address
						printf("   %016" PRIx64 "-%016" PRIx64, offset, offset + pagesize - 1);
					}

					if (present) {
						// Page is present in RAM
						stats.present += pagesize;
						
						// Get PFN
						pfn = entry & 0x007fffffffffffffLL;

						if (globals->verbose && !skip) {
							// Print PFN
							printf(", Present (pfn %016" PRIx64 ")", pfn);
						}

						// Print present marker
						if(globals->map && !skip) {
							if (swapped) printf("B");
							else printf("P");
						}

						gotpagecnt = false;
						if (globals->hkpagecount >= 0) {
							// Get page reference count if we can
							lseek64(globals->hkpagecount, pfn * sizeof(uint64_t), SEEK_SET);						
							b = read(globals->hkpagecount, &pagecnt, sizeof(uint64_t));
							if (b == sizeof(uint64_t)){
								gotpagecnt = true;
							}
						}

						gotpageflags = false;
						if (globals->hkpageflags >= 0) {
							// Get page flags if we can
							lseek64(globals->hkpageflags, pfn * sizeof(uint64_t), SEEK_SET);						
							b = read(globals->hkpageflags, &pageflags, sizeof(uint64_t));
							if (b == sizeof(uint64_t)){
								gotpageflags = true;
							}
						}

						if (gotpageflags) {
							if (pageflags & (1 << 15)) {
								// Compound head
								incompound = true;
								hdpageflags = pageflags;
								hdgotpagecnt = gotpagecnt;
								hdpagecnt = pagecnt;

							} else if(incompound && pageflags & (1 << 16)){
								// Compound tail, use hdpageflags from header

							} else {
								// Not compound
								incompound = false;
								hdpageflags = pageflags;
								hdgotpagecnt = gotpagecnt;
								hdpagecnt = pagecnt;

							}

						} else {
							// Page flags not available
							incompound = false;
							hdgotpagecnt = gotpagecnt;
							hdpagecnt = pagecnt;

						}

						if (gotpagecnt) {
							if (globals->verbose && !skip) {
								// Print reference count
								printf(", RefCnt %" PRIu64, pagecnt);
							}

							if (hdgotpagecnt) {
								// Accumulate private stats
								if (hdpagecnt <= 1) stats.priv += pagesize;
								if (hdpagecnt >= 1) stats.privavg += (pagesize << 8) / hdpagecnt;
							}
						}

						if (gotpageflags) {
							if (globals->verbose && !skip) {
								// Print page flags
								printf(", Flags ");
								dumpflags(pageflags);
							}

							// Accumulate anonymous memory
							if(hdpageflags & (1 << 12)) stats.anon += pagesize;

							// Accumulate referenced memory
							if(hdpageflags & (1 << 2)) stats.refd += pagesize;

							// Accumulate huge pages
							if(hdpageflags & (1 << 17 | 1 << 22)) stats.huge += pagesize;
						}

					}

					if (swapped) {
						// Page is in swap space
						if (!present) {
							stats.swapped += pagesize;
							if(globals->map && !skip) printf("S");
						}

						// Unpack sap file and offset
						swapfile = entry & 0x000000000000001fLL;
						swapoff = (entry & 0x007fffffffffffe0LL) >> 5;

						if(globals->verbose && !skip) {
							// Print swap details
							printf(", Swapped (seg %u offs %016" PRIx64 ")", (unsigned int) swapfile, swapoff);
						}
					}
					
					if (globals->verbose && !skip) {
						printf("\n");
					}
				}
				
				// Move to next page
				offset+=pagesize;
			}

			// Write not present range
			flushnp(globals, &npstart, offset, skip);

			if (globals->map && !skip) printf("\n");

			if (globals->summary) {
				// Print summary details
				if(skip) clearstats(&stats);
				else dumpstats(globals, &stats);
			}
		}

		if (line) free(line);

		if (!globals->summary && !globals->map) {
			if (!globals->list) {
				printf("============ Totals ============\n");
			}

			// Print totals
			dumpstats(globals, &stats);
		}
	} while(0);

	if (hpagemap >= 0) close(hpagemap);
	if (hmaps != NULL) fclose(hmaps);
		
	return result;
}

void dumpstats(struct global *globals, struct sstats *stats)
{
	if (globals->list) {
		printf(" %8" PRIu64 " %8" PRIu64, stats->size / 1024, stats->present / 1024);
		
		if (globals->hkpagecount >= 0) {
			printf(" %8" PRIu64 " %8" PRIu64, stats->priv / 1024, (stats->privavg >> 8) / 1024);
		}
		
		if (globals->hkpageflags >= 0) {
			printf(" %8" PRIu64 " %8" PRIu64 " %8" PRIu64, stats->anon / 1024, stats->refd / 1024, stats->huge / 1024);
		}
		
		printf(" %8" PRIu64, stats->swapped / 1024);

	} else{
		printf("Size:       %8" PRIu64 " kB\n", stats->size / 1024);
		printf("Present:    %8" PRIu64 " kB (%.1f%%)\n", stats->present / 1024, ((double) stats->present / (double) stats->size) * 100.0);
		
		if (globals->hkpagecount >= 0 && stats->present) {
			printf("  Unique:   %8" PRIu64 " kB (%.1f%%)\n", stats->priv / 1024, ((double) stats->priv / (double) stats->present) * 100.0);
			printf("  Average:  %8" PRIu64 " kB (%.1f%%)\n", (stats->privavg >> 8) / 1024, ((double) (stats->privavg >> 8) / (double) stats->present) * 100.0);
		}
		
		if (globals->hkpageflags >= 0 && stats->present) {
			printf("  Anon:     %8" PRIu64 " kB (%.1f%%)\n", stats->anon / 1024, ((double) stats->anon / (double) stats->present) * 100.0);
			printf("  Huge:     %8" PRIu64 " kB (%.1f%%)\n", stats->huge / 1024, ((double) stats->huge / (double) stats->present) * 100.0);
			printf("Referenced: %8" PRIu64 " kB (%.1f%%)\n", stats->refd / 1024, ((double) stats->refd / (double) stats->size) * 100.0);
		}
		
		printf("Swapped:    %8" PRIu64 " kB (%.1f%%)\n", stats->swapped / 1024, ((double) stats->swapped / (double) stats->size) * 100.0);

	}
	
	clearstats(stats);
}

void clearstats(struct sstats *stats)
{
	stats->size = 0;
	stats->present = 0;
	stats->priv = 0;
	stats->privavg = 0;
	stats->anon = 0;
	stats->refd = 0;
	stats->swapped = 0;
	stats->huge = 0;
}

void usage()
{
	printf("Usage: PageMap [-p <pid> [-v | -m] [-s] [-w]]\n"
	       "   where: -p <pid>  Process ID to dump\n"
	       "          -v        Dump each present / swapped page frame\n"
	       "          -m        Dump status map of each mapped frame:\n"
		   "                      'P' = present\n"
		   "                      'S' = swapped\n"
		   "                      'B' = present and swapped\n"
		   "                      '.' = not present\n"
	       "          -s        Print statistics for each mapped section\n"
	       "          -w        Only process writable sections\n");
}

void printsize(uint64_t size)
{
	int mult = 0;
	const char *unit;
	
	while (size > (mult == 0 ? 1024 : 8192)) {
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
	
	printf("[%4" PRIu64 " %2s]",size,unit);
}

void dumpflags(uint64_t flags)
{
	int loop;
	int first=1;
	
	for (loop = 0; loop < 64; loop++) {
		if (flags & 1) {
			if(first){
				printf("[");
				first = 0;
			} else{
				printf(" ");
			}
			
			switch(loop){
			// Taken from Linux/include/uapi/linux/kernel-page-flags.h:
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
			case 22:
				printf("THP");
				break;
			case 23:
				printf("BALLOON");
				break;
			case 24:
				printf("ZERO_PAGE");
				break;

			// Taken from Linux/include/linux/kernel-page-flags.h (subject to change):
			case 32:
				printf("RESERVED?");
				break;
			case 33:
				printf("MLOCKED?");
				break;
			case 34:
				printf("MAPPEDTODISK?");
				break;
			case 35:
				printf("PRIVATE?");
				break;
			case 36:
				printf("PRIVATE_2?");
				break;
			case 37:
				printf("OWNER_PRIVATE?");
				break;
			case 38:
				printf("ARCH?");
				break;
			case 39:
				printf("UNCACHED?");
				break;
			case 40:
				printf("SOFTDIRTY?");
				break;
				
			default:
				printf("<%d>",loop);
				break;
			}
		}

		flags >>= 1;
	}

	if (first) printf("[]");
	else printf("]");
}

void flushnp(struct global *globals, uint64_t *npstart, uint64_t offset, bool skip)
{
	if (*npstart != UINT64_MAX) {
		if (globals->verbose && !skip) {
			printf("   %016" PRIx64 "-%016" PRIx64, *npstart, offset - 1);
			printf(", Not present ");
			printsize(offset - *npstart);
			printf("\n");
		}

		*npstart = UINT64_MAX;
	}
}

#define MAX_CMDLINE 200

void tidy_buf(char *buf, int b)
{
	char *ch;
	int loop;

	buf[b - 1] = '\x0';
	for (ch = buf, loop = 0; loop < b - 1; loop++, ch++) {
		if (*ch == '\x0') *ch = ' ';
		else if (!isprint(*ch)) *ch = '.';
	}
}

bool cmdlinefrom(uint64_t pid, const char* file, char* buf, int width)
{
	bool ok = false;
	int hcmdline;
	char path[PATH_MAX];
	int b;

	sprintf(path, "/proc/%" PRIu64 "/%s", pid, file);
	hcmdline = open(path, O_RDONLY);

	if (hcmdline >= 0) {
		b = read(hcmdline, buf, width);

		if (b > 0) {
			tidy_buf(buf, b);
			ok = true;
		}

		close(hcmdline);
	}

	return ok;
}

void printcmdline(uint64_t pid, int width)
{
	char *buf;
	
	if (width == 0) width = MAX_CMDLINE;
	buf = (char *) malloc(width);

	if (cmdlinefrom(pid, "cmdline", buf, width)) {
		printf("%s", buf);
	} else if (cmdlinefrom(pid, "comm", buf, width)) {
		printf("[%s]", buf);
	} else {
		printf("<Unknown>");
	}

	free(buf);
}
