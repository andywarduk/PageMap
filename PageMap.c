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

#define RET_OK 0
#define RET_HELP 1
#define RET_2PROCS 2
#define RET_BADPID 3
#define RET_ARGREQ 4
#define RET_BADARG 5
#define RET_BADARGCOMB 6
#define RET_PROCSCAN 7

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
	uint64_t last_pid;
	uint64_t tid;
	bool threads;
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

int parse_args(struct global *globals, int argc, char **argv);
bool parse_pid(struct global *globals, char *string);
void initialise(struct global *globals);
void cleanup(struct global *globals);
void usage();
void printsize(uint64_t size);
void dumpflags(uint64_t flags);
void flushnp(struct global *globals, uint64_t *npstart, uint64_t offset, bool skip);
int dumppid(struct global *globals);
int dumpall(struct global *globals);
void dumpall_pid(struct global *globals, uint64_t pid, uint64_t tid, int *printed, bool *needhdg, int procwidth);
int dumpall_pid_threads(struct global *globals, uint64_t pid, int *printed, bool *needhdg, int procwidth);
void dumpstats(struct global *globals, struct sstats *stats);
void clearstats(struct sstats *stats);
void printcmdline(uint64_t pid, int width);

int main(int argc, char **argv)
{
	struct global globals;
	int result;

	// Initialise globals
	initialise(&globals);

	// Parse command line arguments
	result = parse_args(&globals, argc, argv);

	if (result != RET_OK) {
		usage();
		return result;
	}

	// Main process
	if (globals.pid && !globals.threads) {
		result = dumppid(&globals);
	} else {
		result = dumpall(&globals);
	}

	// Clean up globals
	cleanup(&globals);
	
	return result;
}

int parse_args(struct global *globals, int argc, char **argv)
{
	int opt;

	// Parse arguments
	while ((opt = getopt(argc, argv, ":hvmswp:t:")) != -1){
		switch (opt) {
		case 'h':
			return RET_HELP;

		case 'v':
			globals->verbose = true;
			break;

		case 'm':
			globals->map = true;
			break;

		case 's':
			globals->summary = true;
			break;

		case 'w':
			globals->writable = true;
			break;

		case 'p':
			if (globals->pid != 0) {
				fprintf(stderr, "Error: Process ID can only be specified once\n");
				return RET_2PROCS;
			}

			if (!parse_pid(globals, optarg)) {
				fprintf(stderr, "Error: Invalid process / thread ID '%s'\n", optarg);
				return RET_BADPID;
			}

			break;

		case 't':
			globals->threads = true;

			if (globals->pid != 0) {
				fprintf(stderr, "Error: Process ID can only be specified once\n");
				return RET_2PROCS;
			}

			if (!parse_pid(globals, optarg)) {
				fprintf(stderr, "Error: Invalid process ID '%s\n", optarg);
				return RET_BADPID;
			}

			break;

		case ':':
			switch (optopt) {
			case 't':
				globals->threads = true;
				break;

			default:
				fprintf(stderr, "Error: Argument for -%c is required\n", optopt);
				return RET_ARGREQ;

			}

			break;

		default:
			fprintf(stderr, "Error: Unrecognised argument: %c\n", optopt);
			return RET_BADARG;

		}
	}

	if (optind != argc){
		fprintf(stderr, "Error: Unrecognised argument: %s\n", argv[optind]);
		return RET_BADARG;
	}

	if (globals->verbose || globals->map || globals->summary || globals->writable) {
		if (globals->pid == 0 || globals->threads) {
			fprintf(stderr, "Error: Options require a single PID specified with -p only\n");
			return RET_BADARGCOMB;
		}
	}

	if (globals->verbose && globals->map) {
		fprintf(stderr, "Error: -v and -m can't be used together");
		return RET_BADARGCOMB;
	}

	return RET_OK;
}

bool parse_pid(struct global *globals, char *string)
{
	if (strcmp(string, "self") == 0) {
		// Use current pid
		globals->pid = getpid();

	} else {
		// Get pid
		char *end;

		errno = 0;
		globals->pid = strtoull(string, &end, 10);

		if (errno != 0 || *end != '\x0') {
			return false;
		}

	}

	globals->tid = globals->pid;

	return true;
}

void usage()
{
	printf("Usage: PageMap [-t [<pid>] | [-p <pid> [-v | -m] [-s] [-w]]]\n"
	       "   where: -p <pid>    Process / thread ID to dump\n"
	       "          -v          Dump each present / swapped page frame\n"
	       "          -m          Dump status map of each mapped frame:\n"
		   "                        'P' = present\n"
		   "                        'S' = swapped\n"
		   "                        'B' = present and swapped\n"
		   "                        '.' = not present\n"
	       "          -s          Print statistics for each mapped section\n"
	       "          -w          Only process writable sections\n"
	       "          -t [<pid>]  Display all threads for each process\n"
		   "          -h          Show this help\n");
}

void initialise(struct global *globals)
{
	struct winsize window_size;

	globals->verbose = false;
	globals->summary = false;
	globals->map = false;
	globals->writable = false;
	globals->list = false;
	globals->pid = 0;
	globals->last_pid = UINT64_MAX;
	globals->tid = 0;
	globals->threads = false;
	
	// Try and open kernel page stats
	globals->hkpagecount = open("/proc/kpagecount", O_RDONLY);
	globals->hkpageflags = open("/proc/kpageflags", O_RDONLY);

	// Get terminal dimensions
	if (ioctl(fileno(stdout), TIOCGWINSZ, &window_size) == 0){
		globals->terminal = true;
		globals->termwidth = (int) window_size.ws_col;
		globals->termheight = (int) window_size.ws_row;
	} else{
		globals->terminal = false;
		globals->termwidth = 0;
		globals->termheight = 0;
	}
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
			if (isdigit(*ch)) result = 1;
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
	int result = RET_OK;
	bool needhdg = true;
	int printed = 0;
	int statwidth;
	int procwidth;
	
	statwidth = 10;
	if (globals->threads) statwidth += 1 + 10;
	statwidth += 2 * (1 + 8);
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

	if (globals->pid != 0) {
		result = dumpall_pid_threads(globals, globals->pid, &printed, &needhdg, procwidth);

	} else {
		struct dirent **entries = NULL;
		int nent;
		int loop;

		nent = scandir("/proc", &entries, dumpall_filter, dumpall_cmp);

		if (nent < 0) {
			// Failed to scan /proc
			fprintf(stderr, "Error scanning /proc: ");
			perror(NULL);
			result = RET_PROCSCAN;

		} else {
			// Loop each entry in /proc
			for (loop = 0; loop < nent; loop++) {
				uint64_t pid = strtoull(entries[loop]->d_name, NULL, 10);

				if (globals->threads) {
					// Dump all threads for this PID
					dumpall_pid_threads(globals, pid, &printed, &needhdg, procwidth);
				} else {
					// Just dump this PID
					dumpall_pid(globals, pid, pid, &printed, &needhdg, procwidth);
				}

				free(entries[loop]);
			}

		}

		if (entries != NULL) free(entries);
	}

	return result;
}

int dumpall_pid_threads(struct global *globals, uint64_t pid, int *printed, bool *needhdg, int procwidth)
{
	int result = RET_OK;
	char path[PATH_MAX + 1];
	struct dirent **entries = NULL;
	int nent;
	int loop;

	sprintf(path, "/proc/%" PRIu64 "/task", pid);

	nent = scandir(path, &entries, dumpall_filter, dumpall_cmp);

	if (nent < 0) {
		// Failed to scan /proc/n/task
		fprintf(stderr, "Error scanning %s: ", path);
		perror(NULL);
		result = RET_PROCSCAN;

	} else {
		// Loop each entry in /proc/n/task
		for (loop = 0; loop < nent; loop++) {
			uint64_t tid = strtoull(entries[loop]->d_name, NULL, 10);

			// Just dump this TID
			dumpall_pid(globals, pid, tid, printed, needhdg, procwidth);

			free(entries[loop]);
		}

	}

	if (entries != NULL) free(entries);

	return result;
}

void dumpall_pid(struct global *globals, uint64_t pid, uint64_t tid, int *printed, bool *needhdg, int procwidth)
{
	if (*needhdg) {
		printf("====== PID");
		
		if (globals->threads) {
			printf("        TID");
		}

		printf("     Size  Present");

		if (globals->hkpagecount >= 0) {
			printf("  Private  Average");
		}

		if (globals->hkpageflags >= 0) {
			printf("     Anon    Ref'd     Huge");
		}

		printf("  Swapped Process ======\n");
		*needhdg = false;
	}

	globals->pid = pid;
	globals->tid = tid;

	if (tid > 0 && dumppid(globals) == 0) {
		printf(" ");
		printcmdline(globals->tid, procwidth);
		printf("\n");
		if (globals->terminal && globals->termheight > 2 && ++*printed % (globals->termheight - 1) == 0) *needhdg = true;
	}
}

int dumppid(struct global *globals)
{
	int result = 0;
	
	bool skip;
	char *end;
	char path[PATH_MAX + 1];
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

	uint64_t pagecnt = 0;
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
		sprintf(path, "/proc/%" PRIu64 "/pagemap", globals->tid);
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
		sprintf(path, "/proc/%" PRIu64 "/maps", globals->tid);
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

		if (globals->list) {
			if (globals->pid != globals->last_pid) {
				printf("%10" PRIu64, globals->pid);
				globals->last_pid = globals->pid;
			} else {
				printf("          ");
			}

			if (globals->threads) {
				printf(" %10" PRIu64, globals->tid);
			}
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
							printf(", Present");

							if (pfn != 0) {
								printf(" (pfn %016" PRIx64 ")", pfn);
							}
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

						// Print present marker
						if(globals->map && !skip) {
							// If swapped or SWAPCACHE print 'B'
							if (swapped || (gotpageflags && (pageflags & (1 << 13)))) printf("B");
							else printf("P");
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

						// Unpack swap file and offset
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
	char path[PATH_MAX + 1];
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
