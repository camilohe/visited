/* visited -- fast winroute proxy logs analyzer.
 *
 * Copyright (C) 2011-2012 Camilo E. Hidalgo Estevez <camiloehe@gmail.com>
 * Based on Visitors by Salvatore Sanfilippo <antirez@invece.org>
 * for more information visit http://www.hping.org/visitors
 * All Rights Reserved.
 *
 * This software is released under the terms of the BSD license.
 * Read the COPYING file in this distribution for more details. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <locale.h>
#include <ctype.h>

#include "aht.h"
#include "antigetopt.h"
#include "sleep.h"
#include "blacklist.h"

/* Max length of an error stored in the visitors handle */
#define VI_ERROR_MAX 1024
/* Max length of a log line */
#define VI_LINE_MAX 4096
/* Max number of filenames in the command line */
#define VI_FILENAMES_MAX 1024
/* Max number of prefixes in the command line */
#define VI_PREFIXES_MAX 1024
/* Max number of --grep --exclude patterns in the command line */
#define VI_GREP_PATTERNS_MAX 1024
/* Abbreviation length for HTML outputs */
#define VI_HTML_ABBR_LEN 100
/* Max length of a log entry date */
#define VI_DATE_MAX 64
/* Version as a string */
#define VI_VERSION_STR "0.25"

/*------------------------------- data structures ----------------------------*/

/* visited handle */
struct vih {
	int startt;
	int endt;
	int processed;
	int invalid;
	int blacklisted;

	int hour_hits[24];
	int hour_size[24];
	int weekday_hits[7];
	int weekday_size[7];
	int weekdayhour_hits[7][24]; /* hour and weekday combined data */
	int weekdayhour_size[7][24]; /* hour and weekday combined data */
	int monthday_hits[12][31]; /* month and day combined data */
	int monthday_size[12][31]; /* month and day combined data */

	struct hashtable pages_hits;
	struct hashtable pages_size;
	struct hashtable sites_hits;
	struct hashtable sites_size;

	struct hashtable users_hits;
	struct hashtable users_size;
	struct hashtable hosts_hits;
	struct hashtable hosts_size;
	struct hashtable codes_hits;
	struct hashtable codes_size;
	struct hashtable verbs_hits;
	struct hashtable verbs_size;

	struct hashtable types_hits;
	struct hashtable types_size;

	struct hashtable month_hits;
	struct hashtable month_size;

	struct hashtable error404;

	struct hashtable date;
	char *error;
};

/* info associated with a line of log */
struct logline {
	char *host;
	char *user;
	char *date;
	char *hour;
	char *timezone;
	char *req;
	char *code;
	char *verb;
	long size;
	time_t time;
	struct tm tm;
};

/* output module structure. See below for the definition of
 * the text and html output modules. */
struct outputmodule {
	void (*print_header)(FILE *fp);
	void (*print_footer)(FILE *fp);
	void (*print_title)(FILE *fp, char *title);
	void (*print_subtitle)(FILE *fp, char *title);
	void (*print_numkey_info)(FILE *fp, char *key, int val);
	void (*print_keykey_entry)(FILE *fp, char *key1, char *key2, int num);
	void (*print_numkey_entry)(FILE *fp, char *key, int val, char *link,
	                           int num);
	void (*print_numkeybar_entry)(FILE *fp, char *key, int max, int tot,
	                              int this);
	void (*print_numkeycomparativebar_entry)(FILE *fp, char *key, int tot,
	        int this);
	void (*print_bidimentional_map)(FILE *fp, int xlen, int ylen,
	                                char **xlabel, char **ylabel, int *value);
	void (*print_hline)(FILE *fp);
	void (*print_credits)(FILE *fp);
	void (*print_report_link)(FILE *fp, char *report);
};

/* Just a string with cached length */
struct vistring {
	char *str;
	int len;
};

/* Grep pattern for --grep --exclude */
#define VI_PATTERNTYPE_GREP 0
#define VI_PATTERNTYPE_EXCLUDE 1
struct greppat {
	int type;
	char *pattern;
};

/* ---------------------- global configuration parameters ------------------- */
int Config_debug = 0;
int Config_max_requests = 50;
int Config_max_pages = 50;
int Config_max_images = 50;
int Config_max_error404 = 50;
int Config_max_codes = 50;
int Config_max_sites = 50;
int Config_max_types = 50;
int Config_max_hosts = 50;
int Config_process_codes = 0;
int Config_process_weekdayhour_map = 0;
int Config_process_monthday_map = 0;
int Config_process_users = 0;
int Config_process_verbs = 0;
int Config_process_sites = 0;
int Config_process_types = 0;
int Config_process_hosts = 0;
int Config_process_error404 = 0;
int Config_process_monthly_hits = 1;
int Config_tail_mode = 0;
int Config_stream_mode = 0;
int Config_update_every = 60*10; /* update every 10 minutes for default. */
int Config_reset_every = 0;	/* never reset for default */
int Config_time_delta = 0;	/* adjustable time difference */
int Config_filter_spam = 0;
int Config_ignore_404 = 0;
char *Config_output_file = NULL; /* stdout if not set. */
struct outputmodule *Output = NULL; /* intialized to 'text' in main() */

/* Prefixes */
int Config_prefix_num = 0;	/* number of set prefixes */
struct vistring Config_prefix[VI_PREFIXES_MAX];

/* Grep/Exclude array */
struct greppat Config_grep_pattern[VI_GREP_PATTERNS_MAX];
int Config_grep_pattern_num = 0;    /* number of set patterns */

/*----------------------------------- Tables ---------------------------------*/
static char *vi_wdname[7] = {"Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"};
#if 0
static int vi_monthdays[12] = {31, 29, 31, 30, 31, 30 , 31, 31, 30, 31, 30, 31};
#endif

/* -------------------------------- prototypes ------------------------------ */
void vi_clear_error(struct vih *vih);
void vi_tail(int filec, char **filev);

/*------------------- Options parsing help functions ------------------------ */
void ConfigAddGrepPattern(char *pattern, int type) {
	char *s;
	int len = strlen(pattern);

	if (Config_grep_pattern_num == VI_GREP_PATTERNS_MAX) {
		fprintf(stderr, "Too many grep/exclude options specified\n");
		exit(1);
	}
	s = malloc(strlen(pattern)+3);
	s[0] = '*';
	memcpy(s+1, pattern, len);
	s[len+1] = '*';
	s[len+2] = '\0';
	Config_grep_pattern[Config_grep_pattern_num].type = type;
	Config_grep_pattern[Config_grep_pattern_num].pattern = s;
	Config_grep_pattern_num++;
}

/*------------------------------ support functions -------------------------- */
/* Returns non-zero if the link seems like a google link, zero otherwise.
 * Note that this function only checks for a prefix of www.google.<something>.
 * so may be fooled. */
int vi_is_google_link(char *s) {
	return !strncmp(s, "http://www.google.", 18);
}

/* Returns non-zero if the url matches some user-specified prefix.
 * being a link "internal" to the site. Otherwise zero is returned.
 *
 * When there is a match, the value returned is the length of
 * the matching prefix. */
int vi_is_internal_link(char *url) {
	int i, l;

	if (!Config_prefix_num) return 0; /* no prefixes set? */
	l = strlen(url);
	for (i = 0; i < Config_prefix_num; i++) {
		if (Config_prefix[i].len <= l &&
		        !strncasecmp(url, Config_prefix[i].str,
		                     Config_prefix[i].len)) {
			return Config_prefix[i].len;
		}
	}
	return 0;
}

/* returns non-zero if the URL 's' seems a real page. */
int vi_is_pageview(char *s) {
	int l = strlen(s);
	char *end = s + l; /* point to the nul term */
	char *dot, *slash;

	if (s[l-1] == '/') return 1;
	if (l >= 6 &&
	        (!memcmp(end-5, ".html", 5) ||
	         !memcmp(end-4, ".htm", 4) ||
	         !memcmp(end-4, ".php", 4) ||
	         !memcmp(end-4, ".asp", 4) ||
	         !memcmp(end-4, ".jsp", 4) ||
	         !memcmp(end-4, ".xdl", 4) ||
	         !memcmp(end-5, ".xhtml", 5) ||
	         !memcmp(end-4, ".xml", 4) ||
	         !memcmp(end-4, ".cgi", 4) ||
	         !memcmp(end-3, ".pl", 3) ||
	         !memcmp(end-6, ".shtml", 6) ||
	         !memcmp(end-5, ".HTML", 5) ||
	         !memcmp(end-4, ".HTM", 4) ||
	         !memcmp(end-4, ".PHP", 4) ||
	         !memcmp(end-4, ".ASP", 4) ||
	         !memcmp(end-4, ".JSP", 4) ||
	         !memcmp(end-4, ".XDL", 4) ||
	         !memcmp(end-6, ".XHTML", 6) ||
	         !memcmp(end-4, ".XML", 4) ||
	         !memcmp(end-4, ".CGI", 4) ||
	         !memcmp(end-3, ".PL", 3) ||
	         !memcmp(end-6, ".SHTML", 6))) return 1;
	dot = strrchr(s, '.');
	if (!dot) return 1;
	slash = strrchr(s, '/');
	if (slash && slash > dot) return 1;
	return 0;
}

/* returns non-zero if 'ip' seems a string representing an IP address
 * like "1.2.3.4". Note that 'ip' is always an IP or an hostname
 * so this function actually test if the string pointed by 'ip' only
 * contains characters in the "[0-9.]" set */
int vi_is_numeric_address(char *ip) {
	unsigned int l = strlen(ip);
	return strspn(ip, "0123456789.") == l;
}

/* returns the time converted into a time_t value.
 * On error (time_t) -1 is returned.
 * Note that this function is specific for the following format:
 * "10/May/2004:04:15:33". Works if the month is not an abbreviation, or if the
 * year is abbreviated to only the last two digits.
 * The time can be omitted like in "10/May/2004". */
time_t parse_date(char *s, struct tm *tmptr) {
	struct tm tm;
	time_t t;
	char *months[] = {
		"jan", "feb", "mar", "apr", "may", "jun",
		"jul", "aug", "sep", "oct", "nov", "dec",
	};
	char *day, *month, *year, *time = NULL;
	char monthaux[32];
	int i, len;

	/* make a copy to mess with it */
	len = strlen(s);
	if (len >= 32) goto fmterr;
	memcpy(monthaux, s, len);
	monthaux[len] = '\0';

	/* Inizialize the tm structure. We just fill three fields */
	tm.tm_sec = 0;
	tm.tm_min = 0;
	tm.tm_hour = 0;
	tm.tm_mday = 0;
	tm.tm_mon = 0;
	tm.tm_year = 0;
	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = -1;

	/* search delimiters */
	day = monthaux;
	if ((month = strchr(day, '/')) == NULL) goto fmterr;
	*month++ = '\0';
	if ((year = strchr(month, '/')) == NULL) goto fmterr;
	*year++ = '\0';
	/* time, optional for this parser. */
	if ((time = strchr(year, ':')) != NULL) {
		*time++ = '\0';
	}
	/* convert day */
	tm.tm_mday = atoi(day);
	if (tm.tm_mday < 1 || tm.tm_mday > 31) goto fmterr;
	/* convert month */
	if (strlen(month) < 3) goto fmterr;
	month[0] = tolower(month[0]);
	month[1] = tolower(month[1]);
	month[2] = tolower(month[2]);
	for (i = 0; i < 12; i++) {
		if (memcmp(month, months[i], 3) == 0) break;
	}
	if (i == 12) goto fmterr;
	tm.tm_mon = i;
	/* convert year */
	tm.tm_year = atoi(year);
	if (tm.tm_year > 100) {
		if (tm.tm_year < 1900 || tm.tm_year > 2500) goto fmterr;
		tm.tm_year -= 1900;
	} else {
		/* if the year is in two-digits form, the 0 - 68 range
		 * is converted to 2000 - 2068 */
		if (tm.tm_year < 69)
			tm.tm_year += 100;
	}
	/* convert time */
	if (time) { /* format is HH:MM:SS */
		if (strlen(time) < 8) goto fmterr;
		tm.tm_hour = ((time[0]-'0')*10)+(time[1]-'0');
		if (tm.tm_hour < 0 || tm.tm_hour > 23) goto fmterr;
		tm.tm_min = ((time[3]-'0')*10)+(time[4]-'0');
		if (tm.tm_min < 0 || tm.tm_min > 59) goto fmterr;
		tm.tm_sec = ((time[6]-'0')*10)+(time[7]-'0');
		if (tm.tm_sec < 0 || tm.tm_sec > 60) goto fmterr;
	}
	t = mktime(&tm);
	if (t == (time_t)-1) goto fmterr;
	t += (Config_time_delta*3600);
	if (tmptr) {
		struct tm *auxtm;

		if ((auxtm = localtime(&t)) != NULL)
			*tmptr = *auxtm;
	}
	return t;

fmterr: /* format error */
	return (time_t) -1;
}

/* returns 1 if the given date is Saturday or Sunday.
 * Zero is otherwise returned. */
int vi_is_weekend(char *s) {
	struct tm tm;

	if (parse_date(s, &tm) != (time_t)-1) {
		if (tm.tm_wday == 0 || tm.tm_wday == 6)
			return 1;
	}
	return 0;
}

#if 0
/* Returns true if 'year' is a leap year. */
int isleap(int year) {
	int conda, condb, condc;

	conda = (year%4) == 0;
	condb = (year%100) == 0;
	condc = (year%400) == 0;
	return conda && !(condb && !condc);
}
#endif

/* URL decoding and white spaces trimming function.
 * Input: the encoded string 's'.
 * Output: the decoded string written at 'd' that has room for at least 'n'
 * bytes of data. */
void vi_urldecode(char *d, char *s, int n) {
	char *start = d;
	if (n < 1) return;
	while(*s && n > 1) {
		int c = *s;
		switch(c) {
		case '+':
			c = ' ';
			break;
		case '%':
			if (*(s+1) && *(s+2)) {
				int high = toupper(*(s+1));
				int low = toupper(*(s+2));

				if (high <= '9') high -= '0';
				else high = (high - 'A') + 10;
				if (low <= '9') low -= '0';
				else low = (low - 'A') + 10;
				c = (high << 4)+low;
				s += 2;
			}
			break;
		}
		if (c != ' ' || d != start) {
			*d++ = c;
			n--;
		}
		s++;
	}
	/* Right trim */
	*d = '\0';
	d--;
	while (d >= start && *d == ' ') {
		*d = '\0';
		d--;
	}
}

/* URL encoding function
 * Input: the unencoded string 's'.
 * Output: the url-encoded string written at 'd' that has room for at least 'n'
 * bytes of data. */
void vi_urlencode(char *d, char *s, int n) {
	if (n < 1) return;
	n--;
	while(*s && n > 0) {
		int c = *s;
		if ((c >= 'A' && c <= 'Z') ||
		        (c >= 'a' && c <= 'z') ||
		        (c >= '0' && c <= '9')) {
			*d++ = c;
			n--;
		} else if (c == ' ') {
			*d++ = '+';
			n--;
		} else if (c == '\n') {
			if (n < 6) break;
			memcpy(d, "%0d%0a", 6);
			d += 6;
			n -= 6;
		} else {
			unsigned int t;
			char *hexset = "0123456789abcdef";

			if (n < 3) break;
			t = (unsigned) c;
			*d++ = '%';
			*d++ = hexset [(t & 0xF0) >> 4];
			*d++ = hexset [(t & 0x0F)];
			n -= 3;
		}
		s++;
	}
	*d = '\0';
}

/* Convert a nul-term string to lowercase in place */
void vi_strtolower(char *s) {
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

/* Note: the following function strlcat and strlcpy are (possibly) modified
 * version of OpenBSD's functions. Original copyright notice:
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * Originally under the BSD license. */
int vi_strlcpy(char *dst, char *src, int siz) {
	char *d = dst;
	const char *s = src;
	int n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}
	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';              /* NUL-terminate dst */
		while (*s++)
			;
	}
	return(s - src - 1);    /* count does not include NUL */
}

int vi_strlcat(char *dst, const char *src, int siz) {
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));       /* count does not include NUL */
}

/* Returns non-zero if the url matches one of the keywords in
 * blacklist.h, otherwise zero is returned. Warning!!! This function
 * run time is proportional to the size of blacklist.h, so it is
 * very slow. */
int vi_is_blacklisted_url(struct vih *vih, char *url) {
	unsigned int i;

	for (i = 0; i < VI_BLACKLIST_LEN; i++) {
		if (strstr(url, vi_blacklist[i])) {
			vih->blacklisted++;
			return 1;
		}
	}
	return 0;
}

/* Glob-style pattern matching. */
int vi_match_len(const char *pattern, int patternLen,
                 const char *string, int stringLen, int nocase) {
	while(patternLen) {
		switch(pattern[0]) {
		case '*':
			while (pattern[1] == '*') {
				pattern++;
				patternLen--;
			}
			if (patternLen == 1)
				return 1; /* match */
			while(stringLen) {
				if (vi_match_len(pattern+1, patternLen-1,
				                 string, stringLen, nocase))
					return 1; /* match */
				string++;
				stringLen--;
			}
			return 0; /* no match */
			break;
		case '?':
			if (stringLen == 0)
				return 0; /* no match */
			string++;
			stringLen--;
			break;
		case '[': {
			int not, match;

			pattern++;
			patternLen--;
			not = pattern[0] == '^';
			if (not) {
				pattern++;
				patternLen--;
			}
			match = 0;
			while(1) {
				if (pattern[0] == '\\') {
					pattern++;
					patternLen--;
					if (pattern[0] == string[0])
						match = 1;
				} else if (pattern[0] == ']') {
					break;
				} else if (patternLen == 0) {
					pattern--;
					patternLen++;
					break;
				} else if (pattern[1] == '-' && patternLen >= 3) {
					int start = pattern[0];
					int end = pattern[2];
					int c = string[0];
					if (start > end) {
						int t = start;
						start = end;
						end = t;
					}
					if (nocase) {
						start = tolower(start);
						end = tolower(end);
						c = tolower(c);
					}
					pattern += 2;
					patternLen -= 2;
					if (c >= start && c <= end)
						match = 1;
				} else {
					if (!nocase) {
						if (pattern[0] == string[0])
							match = 1;
					} else {
						if (tolower((int)pattern[0]) == tolower((int)string[0]))
							match = 1;
					}
				}
				pattern++;
				patternLen--;
			}
			if (not)
				match = !match;
			if (!match)
				return 0; /* no match */
			string++;
			stringLen--;
			break;
		}
		case '\\':
			if (patternLen >= 2) {
				pattern++;
				patternLen--;
			}
			/* fall through */
		default:
			if (!nocase) {
				if (pattern[0] != string[0])
					return 0; /* no match */
			} else {
				if (tolower((int)pattern[0]) != tolower((int)string[0]))
					return 0; /* no match */
			}
			string++;
			stringLen--;
			break;
		}
		pattern++;
		patternLen--;
		if (stringLen == 0) {
			while(*pattern == '*') {
				pattern++;
				patternLen--;
			}
			break;
		}
	}
	if (patternLen == 0 && stringLen == 0)
		return 1;
	return 0;
}

/* Like vi_match_len but more handly if used against nul-term strings. */
int vi_match(const char *pattern, const char *string, int nocase) {
	int patternLen = strlen(pattern);
	int stringLen = strlen(string);
	return vi_match_len(pattern, patternLen, string, stringLen, nocase);
}

/*-------------------------- visited handler functions --------------------- */
/* Init the hashtable with methods suitable for an "occurrences counter" */
void vi_ht_init(struct hashtable *ht) {
	ht_init(ht);
	ht_set_hash(ht, ht_hash_string);
	ht_set_key_destructor(ht, ht_destructor_free);
	ht_set_val_destructor(ht, ht_no_destructor);
	ht_set_key_compare(ht, ht_compare_string);
}

/* Reset the weekday/hour info in the visited handler. */
void vi_reset_combined_maps(struct vih *vih) {
	int i, j;

	for (i = 0; i < 24; i++) {
		vih->hour_hits[i] = 0;
		vih->hour_size[i] = 0;
		for (j = 0; j < 7; j++) {
			vih->weekdayhour_hits[j][i] = 0;
			vih->weekdayhour_size[j][i] = 0;
		}
	}
	for (i = 0; i < 7; i++) vih->weekday_hits[i] = 0;
	for (i = 0; i < 7; i++) vih->weekday_size[i] = 0;
	for (i = 0; i < 31; i++)
		for (j = 0; j < 12; j++) {
			vih->monthday_hits[j][i] = 0;
			vih->monthday_size[j][i] = 0;
		}
}

/* Reset the hashtables from the handler, that are left
 * in a reusable state (but all empty). */
void vi_reset_hashtables(struct vih *vih) {
	ht_destroy(&vih->users_hits);
	ht_destroy(&vih->users_size);
	ht_destroy(&vih->hosts_hits);
	ht_destroy(&vih->hosts_size);
	ht_destroy(&vih->pages_hits);
	ht_destroy(&vih->pages_size);
	ht_destroy(&vih->sites_hits);
	ht_destroy(&vih->sites_size);
	ht_destroy(&vih->codes_hits);
	ht_destroy(&vih->codes_size);
	ht_destroy(&vih->verbs_hits);
	ht_destroy(&vih->verbs_size);
	ht_destroy(&vih->types_hits);
	ht_destroy(&vih->types_size);
	ht_destroy(&vih->month_hits);
	ht_destroy(&vih->month_size);
	ht_destroy(&vih->error404);
	ht_destroy(&vih->date);
}

/* Reset handler informations to support --reset option in
 * stream mode. */
void vi_reset(struct vih *vih) {
	vi_reset_combined_maps(vih);
	vi_reset_hashtables(vih);
}

/* Return a new visitors handle.
 * On out of memory NULL is returned.
 * The handle obtained with this call must be released with vi_free()
 * when no longer useful. */
struct vih *vi_new(void) {
	struct vih *vih;

	if ((vih = malloc(sizeof(*vih))) == NULL)
		return NULL;
	/* Initialization */
	vih->startt = vih->endt = time(NULL);
	vih->processed = 0;
	vih->invalid = 0;
	vih->blacklisted = 0;
	vi_reset_combined_maps(vih);
	vih->error = NULL;
	vi_ht_init(&vih->users_hits);
	vi_ht_init(&vih->users_size);
	vi_ht_init(&vih->hosts_hits);
	vi_ht_init(&vih->hosts_size);
	vi_ht_init(&vih->pages_hits);
	vi_ht_init(&vih->pages_size);
	vi_ht_init(&vih->sites_hits);
	vi_ht_init(&vih->sites_size);
	vi_ht_init(&vih->codes_hits);
	vi_ht_init(&vih->codes_size);
	vi_ht_init(&vih->verbs_hits);
	vi_ht_init(&vih->verbs_size);
	vi_ht_init(&vih->types_hits);
	vi_ht_init(&vih->types_size);
	vi_ht_init(&vih->month_hits);
	vi_ht_init(&vih->month_size);
	vi_ht_init(&vih->error404);
	vi_ht_init(&vih->date);
	return vih;
}

/* Free an handle created with vi_new(). */
void vi_free(struct vih *vih) {
	if (!vih) return;
	vi_reset_hashtables(vih);
	vi_clear_error(vih);
	free(vih);
}

/* Add a new entry in the counter hashtable. If the key does not
 * exists creates a new entry with "1" as number of hits, otherwise
 * increment the old value.
 *
 * Return the value of hits after the increment or creation. If the
 * returned value is greater than one, the key was already seen.
 *
 * Return 0 on out of memory.
 *
 * NOTE: the pointer of the "value" part of the hashtable entry is
 * used as a counter casting it to a "long" integer. */
int vi_counter_incr(struct hashtable *ht, char *key) {
	char *k;
	unsigned int idx;
	int r;
	long val;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		k = strdup(key);
		if (k == NULL) return 0;
		if (ht_add(ht, k, (void*)1) != HT_OK) {
			free(k);
			return 0;
		}
		return 1;
	} else {
		val = (long) ht_value(ht, idx);
		val++;
		ht_value(ht, idx) = (void*) val;
		return val;
	}
}

/* Similar to vi_counter_incr, but only read the old value of
 * the counter without to alter it. If the specified key does not
 * exists zero is returned. */
int vi_counter_val(struct hashtable *ht, char *key) {
	unsigned int idx;
	int r;
	long val;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		return 0;
	} else {
		val = (long) ht_value(ht, idx);
		return val;
	}
}

/* Add a new entry in the traffic hashtable. If the key does not
 * exists creates a new entry with the size, otherwise adds to
 * the old value.
 *
 * Return the value of size after the increment or creation. If the
 * returned value is greater than zero, the key was already seen.
 *
 * Return 0 on out of memory.
 *
 * NOTE: the pointer of the "value" part of the hashtable entry is
 * used as a total casting it to a "long" integer. */
int vi_traffic_incr(struct hashtable *ht, char *key, long size) {
	char *k;
	unsigned int idx;
	int r;
	long val;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		k = strdup(key);
		if (k == NULL) return 0;
		if (ht_add(ht, k, (void*)1) != HT_OK) {
			free(k);
			return 0;
		}
		return 1;
	} else {
		val = (long) ht_value(ht, idx);
		val += size;
		ht_value(ht, idx) = (void*) val;
		return val;
	}
}

/* Similar to vi_traffic_incr, but only read the old value of
 * the size without altering it. If the specified key does not
 * exists zero is returned. */
int vi_traffic_val(struct hashtable *ht, char *key) {
	unsigned int idx;
	int r;
	long val;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		return 0;
	} else {
		val = (long) ht_value(ht, idx);
		return val;
	}
}

/* Set a key/value pair inside the hash table with
 * a create-else-replace semantic.
 *
 * Return non-zero on out of memory. */
int vi_replace(struct hashtable *ht, char *key, char *value) {
	char *k, *v;

	k = strdup(key);
	v = strdup(value);
	if (!k || !v) goto err;
	if (ht_replace(ht, k, v) != HT_OK)
		goto err;
	return 0;
err:
	if (k) free(k);
	if (v) free(v);
	return 1;
}

/* Replace the time value of the given key with the new one if this
 * is newer/older of the old one. If the key is new, it's just added
 * to the hash table with the specified time as value.
 *
 * If the 'ifolder' flag is set, values are replaced with older one,
 * otherwise with newer.
 * This function is only used by wrappers replace_if_older() and
 * replace_if_newer().
 *
 * Return 0 on success, non-zero on out of memory. */
int vi_replace_time(struct hashtable *ht, char *key, time_t time, int ifolder) {
	char *k = NULL;
	unsigned int idx;
	int r;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		k = strdup(key);
		if (!k) goto err;
		if (ht_add(ht, k, (void*)time) != HT_OK) goto err;
	} else {
		time_t oldt = (time_t) ht_value(ht, idx);
		/* Update the date if this one is older/nwer. */
		if (ifolder) {
			if (time < oldt)
				ht_value(ht, idx) = (void*) time;
		} else {
			if (time > oldt)
				ht_value(ht, idx) = (void*) time;
		}
	}
	return 0;
err:
	if (k) free(k);
	return 1;
}

/* see vi_replace_time */
int vi_replace_if_older(struct hashtable *ht, char *key, time_t time) {
	return vi_replace_time(ht, key, time, 1);
}

/* see vi_replace_time */
int vi_replace_if_newer(struct hashtable *ht, char *key, time_t time) {
	return vi_replace_time(ht, key, time, 0);
}

/* Set an error in the visitors handle */
void vi_set_error(struct vih *vih, char *fmt, ...) {
	va_list ap;
	char buf[VI_ERROR_MAX];

	va_start(ap, fmt);
	vsnprintf(buf, VI_ERROR_MAX, fmt, ap);
	buf[VI_ERROR_MAX-1] = '\0';
	free(vih->error);
	vih->error = strdup(buf);
	va_end(ap);
}

/* Get the error */
char *vi_get_error(struct vih *vih) {
	if (!vih->error) {
		return "No error";
	}
	return vih->error;
}

/* Clear the error */
void vi_clear_error(struct vih *vih) {
	free(vih->error);
	vih->error = NULL;
}

/*----------------------------------- parsing   ----------------------------- */
/* Parse a line of log, and fill the logline structure with
 * appropriate values. On error (bad line format) non-zero is returned.
 * sample line from apache http log
 * 192.168.206.108 - - [19/Apr/2011:12:17:53 -0500] "GET /images/Ola.gif HTTP/1.1" 200 586 "http://web.cmc.com.cu/" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"
 * host - - [date:time timezone] "verb url ver" code size "referrer" "agent"
 * sample line from kerio winroute http log
 * 192.168.206.15 - Admin [16/Feb/2011:17:19:57 -0500] "GET http://wc.cmc.com.cu:3000/WorldClient.dll?View=Logout HTTP/1.1" 200 10870 +3
 * host - user [date:time timezone] "verb url ver" code size +connections
 */
int vi_parse_line(struct logline *ll, char *l) {
	char *date, *hour, *timezone, *host, *req, *p, *user = NULL, *code, *size, *verb = NULL;
	char *req_end = NULL, *user_end = NULL; //, *code_end = NULL, *size_end = NULL;

	/* Seek the start of the different components */

	/* host */
	host = l;
	/* date */
	if ((date = strchr(l, '[')) == NULL) return 1;
	user_end = date;
	date++;
	/* user */
	user_end--;
	/* Find user start by searching backwards until we find the space after first dash */
	p = user_end;
	p--;
	while (p >= l) {
		if (*p == ' ') {
			user = p;
			break;
		}
		p--;
	}
	if (p != 0) {
		user++;
	} else {
		user = "";
	}

	/* req */
	if ((req = strstr(l, "\"GET")) != NULL ||
	        (req = strstr(l, "\"POST")) != NULL ||
	        (req = strstr(l, "\"HEAD")) != NULL ||
	        (req = strstr(l, "\"CONNECT")) != NULL ||
	        (req = strstr(l, "\"PUT")) != NULL ||
	        (req = strstr(l, "\"PROPFIND")) != NULL ||
	        (req = strstr(l, "\"OPTIONS")) != NULL ||
	        (req = strstr(l, "\"get")) != NULL ||
	        (req = strstr(l, "\"post")) != NULL ||
	        (req = strstr(l, "\"head")) != NULL ||
	        (req = strstr(l, "\"connect")) != NULL ||
	        (req = strstr(l, "\"put")) != NULL ||
	        (req = strstr(l, "\"propfind")) != NULL ||
	        (req = strstr(l, "\"options")) != NULL) {
		req++;
	} else {
		req = "";
	}

	/* Nul-term the components */

	/* host */
	if ((p = strchr(host, ' ')) == NULL) return 1;
	*p = '\0';
	/* user */
	*user_end = '\0';
	/* date */
	if ((p = strchr(date, ']')) == NULL) return 1;
	*p = '\0';
	ll->time = parse_date(date, &ll->tm);
	if (ll->time == (time_t)-1) return 1;
	/* hour */
	if ((p = strchr(date, ':')) == NULL) return 1;
	hour = p+1;
	*p = '\0';
	/* timezone */
	if ((p = strchr(hour, ' ')) == NULL) return 1;
	timezone = p+1;
	*p = '\0';
	/* req */
	if ((p = strchr(req, '"')) == NULL) return 1;
	req_end = p;
	*p = '\0';
	/* code */
	code = p+2;
	if ((p = strchr(code, ' ')) == NULL) return 1;
	*p = '\0';
	/* size */
	size = p+1;
	if ((p = strchr(size, ' ')) == NULL) return 1;
	*p = '\0';
	/* verb */
	if ((p = strchr(req, ' ')) != NULL) {
		verb = req;
		*p = '\0';
		req = p+1;
		/* strip http ver */
		if ((p = strchr(req, ' ')) != NULL)
			*p = '\0';
	}

	/* Fill the structure */
	ll->host = host;
	ll->user = user;
	ll->date = date;
	ll->hour = hour;
	ll->timezone = timezone;
	ll->req = req;
	ll->verb = verb;
	// convert size to KB for storage by shifting right 10 bits to avoid overflow
	ll->size = atol(size) >> 10;
/*	// convert size to MB for storage by shifting right 20 bits to avoid overflow
	ll->size = atol(size) >> 20;*/
	// exit if we got an http code with more than 3 digits
	if (strlen(code) > 3) return 1;
	ll->code = code;
	return 0;
}

/* process the weekday and hour information */
void vi_process_date_and_hour(struct vih *vih, int weekday, int hour, long size) {
	/* Note, the following sanity check is useless in theory. */
	if (weekday < 0 || weekday > 6 || hour < 0 || hour > 23) return;
	vih->weekday_hits[weekday]++;
	vih->weekday_size[weekday] += size;
	vih->hour_hits[hour]++;
	vih->hour_size[hour] += size;
	/* store the combined info. We always compute this information
	 * even if the report is disabled because it's cheap. */
	vih->weekdayhour_hits[weekday][hour]++;
	vih->weekdayhour_size[weekday][hour] += size;
}

/* process the month and day information */
void vi_process_month_and_day(struct vih *vih, int month, int day, long size) {
	if (month < 0 || month > 11 || day < 0 || day > 30) return;
	vih->monthday_hits[month][day]++;
	vih->monthday_size[month][day] += size;
}

/* Process requests populating the pages and sites hash tables.
 * Populate also date and month hash tables if requested 
 * Return non-zero on out of memory. */
int vi_process_requests(struct vih *vih, char *req, long size, char *date) {
	char *p, *site = NULL, *month = "fixme if I'm here!";
	int res;

	/* Don't count internal links (specified by the user
	 * using --prefix options) */
	if (vi_is_internal_link(req)) {
		res = vi_traffic_incr(&vih->pages_size, "Internal Link", size);
		if (res == 0) return 1;
		res = vi_counter_incr(&vih->pages_hits, "Internal Link");
		if (res == 0) return 1;
		return 0;
	}
	res = vi_traffic_incr(&vih->pages_size, req, size);
	if (res == 0) return 1;
	res = vi_counter_incr(&vih->pages_hits, req);
	if (res == 0) return 1;

	/* sites */
	if (Config_process_sites) {
		if ((p = strchr(req, '/')) != NULL) {
			site = p+2;
			/* strip http ver */
			if ((p = strchr(site, '/')) != NULL) {
				// this modifies url so we have to restore it below to avoid side effects
				*p = '\0';
				res = vi_traffic_incr(&vih->sites_size, site, size);
				if (res == 0) return 1;
				res = vi_counter_incr(&vih->sites_hits, site);
				if (res == 0) return 1;
				// restore url to avoid interfering with functions called after this 
				*p = '/';
			}
		}
	}

	/* daily hits */
	res = vi_counter_incr(&vih->date, date);
	if (res == 0) return 1;
	/* monthly hits */
	if (Config_process_monthly_hits) {
		/* Skip the day number. */
		month = strchr(date, '/');
		if (!month) return 0; /* should never happen */
		month++;
		res = vi_counter_incr(&vih->month_hits, month);
		if (res == 0) return 1;
		res = vi_traffic_incr(&vih->month_size, month, size);
		if (res == 0) return 1;
	}
	return 0;
}

/* Process requests populating the types hash table.
 * Return non-zero on out of memory. */
int vi_process_types(struct vih *vih, char *url, long size) {
	int res, c;
	char *dot, *p;
	char urldecoded[VI_LINE_MAX];

	vi_urldecode(urldecoded, url, VI_LINE_MAX);

    // skip the first 3 "/" slashes in proto://host.name/
	c = 0;
	p = urldecoded;
	while (*p && c<3) {
		if (*p == '/') c++;
		p++;
	}
	if (!*p) return 0;
	// get the last "." position 
	dot = strrchr(p, '.');
	// if no dot found, assume no file type given and exit  
	if (!dot) return 0;

    // find file type end by searching the first non digit/alpha char after dot 
	p = dot+1;
	while (*p && isalnum(*p)) {
		if (isalpha(*p))
			*p = tolower(*p); // lowercase it if it is alpha to merge duplicates
		p++;
	}
	if (*p) // we found a non digit/alpha so set to null to end file type string
		*p = '\0';
	
    res = vi_counter_incr(&vih->types_hits, dot);
	if (res == 0) return 1;
	res = vi_traffic_incr(&vih->types_size, dot, size);
	if (res == 0) return 1;
	return 0;
}

/* Process log lines for 404 errors report. */
int vi_process_error404(struct vih *vih, char *l, char *url, int *is404) {
	char urldecoded[VI_LINE_MAX];

	if (is404) *is404 = 0;
	vi_urldecode(urldecoded, url, VI_LINE_MAX);
	if (strstr(l, " 404 ") && !strstr(l, " 200 ")) {
		if (is404) *is404 = 1;
		return !vi_counter_incr(&vih->error404, urldecoded);
	}
	return 0;
}

/* Process codes populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_codes(struct vih *vih, char *code, long size) {
	int res;

	res = vi_traffic_incr(&vih->codes_size, code, size);
	if (res == 0) return 1;
	res = vi_counter_incr(&vih->codes_hits, code);
	if (res == 0) return 1;
	return 0;
}

/* Process verbs populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_verbs(struct vih *vih, char *verb, long size) {
	int res;

	res = vi_traffic_incr(&vih->verbs_size, verb, size);
	if (res == 0) return 1;
	res = vi_counter_incr(&vih->verbs_hits, verb);
	if (res == 0) return 1;
	return 0;
}

/* Process users populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_users(struct vih *vih, char *user, long size) {
	int res;

	res = vi_traffic_incr(&vih->users_size, user, size);
	if (res == 0) return 1;
	res = vi_counter_incr(&vih->users_hits, user);
	if (res == 0) return 1;
	return 0;
}

/* Process hosts populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_hosts(struct vih *vih, char *host, long size) {
	int res;

	res = vi_traffic_incr(&vih->hosts_size, host, size);
	if (res == 0) return 1;
	res = vi_counter_incr(&vih->hosts_hits, host);
	if (res == 0) return 1;
	return 0;
}

/* Match the list of keywords 't' against the string 's', and if
 * a match is found increment the matching keyword in the hashtable.
 * Return zero on success, non-zero on out of memory . */
int vi_counter_incr_matchtable(struct hashtable *ht, char *s, char **t) {
	while(*t) {
		int res;
		if ((*t)[0] == '\0' || strstr(s, *t) != NULL) {
			char *key = *(t+1) ? *(t+1) : *t;
			res = vi_counter_incr(ht, key);
			if (res == 0) return 1;
			return 0;
		}
		t += 2;
	}
	return 0;
}

/* Process Operating Systems populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_os(struct vih *vih, char *agent) {
	/* Order may matter. */
	char *oslist[] = {
		"Windows", NULL,
		"Win98", "Windows",
		"Win95", "Windows",
		"WinNT", "Windows",
		"Win32", "Windows",
		"Linux", NULL,
		"-linux-", "Linux",
		"Macintosh", NULL,
		"Mac_PowerPC", "Macintosh",
		"SunOS", NULL,
		"FreeBSD", NULL,
		"OpenBSD", NULL,
		"NetBSD", NULL,
		"BEOS", NULL,
		"", "Unknown",
		NULL, NULL,
	};
	return 0; /* return vi_counter_incr_matchtable(&vih->os, agent, oslist); */
}

/* Reverse a string in place. Courtesy of Bob Stout. */
char *strrev(char *str) {
	char *p1, *p2;

	if (! str || ! *str)
		return str;

	for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2) {
		*p1 ^= *p2;
		*p2 ^= *p1;
		*p1 ^= *p2;
	}

	return str;
}

/* Match a log line against --grep and --exclude patterns to check
 * if the line must be processed or not. */
int vi_match_line(char *line) {
	int i;

	for (i = 0; i < Config_grep_pattern_num; i++) {
		char *pattern = Config_grep_pattern[i].pattern;
		int nocase = 1;

		/* Patterns starting with 'cs:' are matched in a case-sensitive
		 * way after the 'cs:' prefix is discarded. */
		if (pattern[0] == 'c' && pattern[1] == 's' && pattern[2] == ':') {
			nocase = 0;
			pattern += 3;
		}
		if (vi_match(Config_grep_pattern[i].pattern, line, nocase)) {
			if (Config_grep_pattern[i].type == VI_PATTERNTYPE_EXCLUDE)
				return 0;
		} else {
			if (Config_grep_pattern[i].type == VI_PATTERNTYPE_GREP)
				return 0;
		}
	}
	return 1;
}

/* Process a line of log. Returns non-zero on error. */
int vi_process_line(struct vih *vih, char *l) {
	struct logline ll;
	char origline[VI_LINE_MAX];

	/* Test the line against --grep --exclude patterns before
	 * to process it. */
	if (Config_grep_pattern_num) {
		if (vi_match_line(l) == 0)
			return 0; /* No match? skip. */
	}

	vih->processed++;
	/* Take a copy of the original log line before to
	 * copy it. Will be useful for some processing.
	 * Do it only if required in order to speedup. */
	if (Config_process_error404 || Config_debug)
		vi_strlcpy(origline, l, VI_LINE_MAX);
	/* Split the line and run all the selected processing. */
	if (vi_parse_line(&ll, l) == 0) {
		int seen = 0, is404;

		/* We process 404 errors first, in order to skip
		 * all the other reports if --ignore-404 option is active. */
		if (Config_process_error404 &&
		        vi_process_error404(vih, origline, ll.req, &is404))
			goto oom;
		/* 404 error AND --ignore-404? Stop processing of this line. */
		if (Config_ignore_404 && is404)
			return 0;

		/* The following are processed for every log line */
		if (vi_process_requests(vih, ll.req, ll.size, ll.date)) goto oom;

		vi_process_date_and_hour(vih, (ll.tm.tm_wday+6)%7,
		                         ll.tm.tm_hour, ll.size);
		vi_process_month_and_day(vih, ll.tm.tm_mon, ll.tm.tm_mday-1, ll.size);

		if (Config_process_users &&
		        vi_process_users(vih, ll.user, ll.size)) goto oom;
		if (Config_process_types &&
		        vi_process_types(vih, ll.req, ll.size)) goto oom;
		if (Config_process_codes &&
		        vi_process_codes(vih, ll.code, ll.size)) goto oom;
		if (Config_process_verbs &&
		        vi_process_verbs(vih, ll.verb, ll.size)) goto oom;
		if (Config_process_hosts &&
		        vi_process_hosts(vih, ll.host, ll.size)) goto oom;

		/* The following are processed only for new visits */
		if (seen) return 0;
		
		return 0;
	} else {
		vih->invalid++;
		if (Config_debug)
			fprintf(stderr, "Invalid line: %s\n", origline);
		return 0;
	}
oom:
	vi_set_error(vih, "Out of memory processing data");
	return 1;
}

/* Process the specified log file. Returns zero on success.
 * On error non zero is returned and an error is set in the handle. */
int vi_scan(struct vih *vih, char *filename) {
	FILE *fp;
	char buf[VI_LINE_MAX];
	int use_stdin = 0;

	if (filename[0] == '-' && filename[1] == '\0') {
		/* If we are in stream mode, just return. Stdin
		 * is implicit in this mode and will be read
		 * after all the other files are processed. */
		if (Config_stream_mode) return 0;
		fp = stdin;
		use_stdin = 1;
	} else {
		if ((fp = fopen(filename, "r")) == NULL) {
			vi_set_error(vih, "Unable to open '%s': '%s'", filename, strerror(errno));
			return 1;
		}
	}
	while (fgets(buf, VI_LINE_MAX, fp) != NULL) {
		if (vi_process_line(vih, buf)) {
			fclose(fp);
			fprintf(stderr, "%s: %s\n", filename, vi_get_error(vih));
			return 1;
		}
	}
	if (!use_stdin)
		fclose(fp);
	vih->endt = time(NULL);
	return 0;
}

/* ---------------------------- text output module -------------------------- */
void om_text_print_header(FILE *fp) {
	fp = fp;
	return;
}

void om_text_print_footer(FILE *fp) {
	fp = fp;
	return;
}

void om_text_print_title(FILE *fp, char *title) {
	fprintf(fp, "=== %s ===\n", title);
}

void om_text_print_subtitle(FILE *fp, char *subtitle) {
	fprintf(fp, "--- %s\n", subtitle);
}

void om_text_print_numkey_info(FILE *fp, char *key, int val) {
	fprintf(fp, "* %s: %d\n", key, val);
}

void om_text_print_keykey_entry(FILE *fp, char *key1, char *key2, int num) {
	fprintf(fp, "%d)    %s: %s\n", num, key1, key2);
}

void om_text_print_numkey_entry(FILE *fp, char *key, int val, char *link,
                                int num) {
	link = link; /* avoid warning. Text output don't use this argument. */
	fprintf(fp, "%d)    %s: %d\n", num, key, val);
}

/* Print a bar, c1 and c2 are the colors of the left and right parts.
 * Max is the maximum value of the bar, the bar length is printed
 * to be porportional to max. tot is the "total" needed to compute
 * the precentage value. */
void om_text_print_bar(FILE *fp, int max, int tot, int this, int cols,
                       char c1, char c2) {
	int l;
	float p;
	char *bar;
	if (tot == 0) tot++;
	if (max == 0) max++;
	l = ((float)(cols*this))/max;
	p = ((float)(100*this))/tot;
	bar = malloc(cols+1);
	if (!bar) return;
	memset(bar, c2, cols+1);
	memset(bar, c1, l);
	bar[cols] = '\0';
	fprintf(fp, "%s %02.1f%%", bar, p);
	free(bar);
}

void om_text_print_numkeybar_entry(FILE *fp, char *key, int max, int tot, int this) {
	fprintf(fp, "   %-12s: %-9d |", key, this);
	om_text_print_bar(fp, max, tot, this, 44, '#', ' ');
	fprintf(fp, "\n");
}

void om_text_print_numkeycomparativebar_entry(FILE *fp, char *key, int tot, int this) {
	fprintf(fp, "   %s: %-10d |", key, this);
	om_text_print_bar(fp, tot, tot, this, 44, '#', '.');
	fprintf(fp, "\n");
}

void om_text_print_bidimentional_map(FILE *fp, int xlen, int ylen,
                                     char **xlabel, char **ylabel, int *value) {
	char *asciipal = " .-+#";
	int pallen = strlen(asciipal);
	int x, y, l, max = 0;

	/* Get the max value */
	l = xlen*ylen;
	for (x = 0; x < l; x++)
		if (max < value[x])
			max = value[x];
	if (max == 0) max++; /* avoid division by zero */
	/* print the map */
	for (y = 0; y < ylen; y++) {
		fprintf(fp, "%15s: ", ylabel[y]);
		for (x = 0; x < xlen; x++) {
			int coloridx;
			int val = value[(y*xlen)+x];

			coloridx = ((pallen-1)*val)/max;
			fputc(asciipal[coloridx], fp);
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
	/* print the x-labels in vertical */
	{
		char **p = malloc(sizeof(char*)*xlen);
		/* The 'p' pointers array is initialized at the
		 * start of all the x-labels. */
		for (x = 0; x < xlen; x++)
			p[x] = xlabel[x];
		while(1) {
			int sentinel = 0;
			fprintf(fp, "%15s  ", "");
			for (x = 0; x < xlen; x++) {
				if (*(p[x]) != '\0') {
					fputc(*(p[x]), fp);
					p[x]++;
					sentinel++;
				} else {
					fputc(' ', fp);
				}
			}
			fputc('\n', fp);
			if (sentinel == 0) break;
		}
		free(p);
	}
}

void om_text_print_hline(FILE *fp) {
	fprintf(fp, "\n");
}

void om_text_print_credits(FILE *fp) {
	fprintf(fp, "Statistics generated with VISITED version %s\n",
	        VI_VERSION_STR);
}

void om_text_print_report_link(FILE *fp, char *report) {
	fprintf(fp, "-> %s\n", report);
	return;
}

struct outputmodule OutputModuleText = {
	om_text_print_header,
	om_text_print_footer,
	om_text_print_title,
	om_text_print_subtitle,
	om_text_print_numkey_info,
	om_text_print_keykey_entry,
	om_text_print_numkey_entry,
	om_text_print_numkeybar_entry,
	om_text_print_numkeycomparativebar_entry,
	om_text_print_bidimentional_map,
	om_text_print_hline,
	om_text_print_credits,
	om_text_print_report_link,
};

/* ---------------------------- html output module -------------------------- */
/* Use html entities for special chars. Abbreviates at 'maxlen' if needed. */
void om_html_entities_abbr(FILE *fp, char *s, int maxlen) {
	while(*s) {
		if (maxlen-- == 0) {
			fprintf(fp, "...");
			break;
		}
		switch(*s) {
		case '\'':
			fprintf(fp, "&#39;");
			break;
		case '"':
			fprintf(fp, "&#34;");
			break;
		case '&':
			fprintf(fp, "&amp;");
			break;
		case '<':
			fprintf(fp, "&lt;");
			break;
		case '>':
			fprintf(fp, "&gt;");
			break;
		default:
			fputc(*s, fp);
			break;
		}
		s++;
	}
}

/* A wrapper to om_html_entities_abbr() with a fixed abbreviation length */
void om_html_entities(FILE *fp, char *s) {
	om_html_entities_abbr(fp, s, VI_HTML_ABBR_LEN);
}

void om_html_print_header(FILE *fp) {
	fprintf(fp,
	        "<html>\n"
	        "<head>\n"
	        "<style>\n"
	        "BODY, TD, B, LI, U, DIV, SPAN {\n"
	        "	background-color: #ffffff;\n"
	        "	color: #000000;\n"
	        "	font-family: Verdana, Arial, Helvetica, Sans-Serif;\n"
	        "	font-size: 10px;\n"
	        "}\n"
	        "A {\n"
	        "	color: #0066ff;\n"
	        "	text-decoration: none;\n"
	        "}\n"
	        "A:visited {\n"
	        "	color: #000099;\n"
	        "	text-decoration: none;\n"
	        "}\n"
	        "A:active {\n"
	        "	color: #26a0be;\n"
	        "	text-decoration: none;\n"
	        "}\n"
	        "A:hover {\n"
	        "	color: #ffffff;\n"
	        "	text-decoration: none;\n"
	        "	background-color: #26a0be;\n"
	        "}\n"
	        ".barfill {\n"
	        "	background-color: #96ef94;\n"
	        "	border-left: 1px;\n"
	        "	border-right: 1px;\n"
	        "	border-top: 1px;\n"
	        "	border-bottom: 1px;\n"
	        "	border-color: #4c934a;\n"
	        "	border-style: solid;\n"
	        "	font-size: 10px;\n"
	        "	height: 3px;\n"
	        "	line-height: 4px;\n"
	        "}\n"
	        ".barempty {\n"
	        "	font-size: 10px;\n"
	        "	line-height: 4px;\n"
	        "}\n"
	        ".barleft {\n"
	        "	background-color: #ff9696;\n"
	        "	border-left: 1px;\n"
	        "	border-right: 1px;\n"
	        "	border-top: 1px;\n"
	        "	border-bottom: 1px;\n"
	        "	border-color: #4c934a;\n"
	        "	border-style: solid;\n"
	        "	font-size: 10px;\n"
	        "	height: 3px;\n"
	        "	line-height: 4px;\n"
	        "}\n"
	        ".barright {\n"
	        "	background-color: #f8f8f8;\n"
	        "	border-left: 0px;\n"
	        "	border-right: 1px;\n"
	        "	border-top: 1px;\n"
	        "	border-bottom: 1px;\n"
	        "	border-color: #4c934a;\n"
	        "	border-style: solid;\n"
	        "	font-size: 10px;\n"
	        "	height: 3px;\n"
	        "	line-height: 4px;\n"
	        "}\n"
	        ".title {\n"
	        "	background-color: #007f9e;\n"
	        "	font-size: 12px;\n"
	        "	font-weight: bold;\n"
	        "	padding: 3px;\n"
	        "	color: #ffffff;\n"
	        "}\n"
	        ".reportlink {\n"
	        "	background-color: #ffffff;\n"
	        "	font-size: 12px;\n"
	        "	font-weight: bold;\n"
	        "	color: #000000;\n"
	        "	padding-left: 3px;\n"
	        "}\n"
	        ".subtitle {\n"
	        "	background-color: #007f9e;\n"
	        "	font-size: 12px;\n"
	        "	font-weight: normal;\n"
	        "	padding: 3px;\n"
	        "	color: #ffffff;\n"
	        "}\n"
	        ".info {\n"
	        "	background-color: #badfee;\n"
	        "	font-size: 12px;\n"
	        "	padding-left: 3px;\n"
	        "	padding-right: 3px;\n"
	        "}\n"
	        ".keyentry {\n"
	        "	font-size: 10px;\n"
	        "	padding-left: 2px;\n"
	        "	border-bottom: 1px dashed #bcbcbc;\n"
	        "}\n"
	        ".keyentrywe {\n"
	        "	background-color: #f0f090;\n"
	        "	font-size: 10px;\n"
	        "	padding-left: 2px;\n"
	        "	border-bottom: 1px dashed #bcbcbc;\n"
	        "}\n"
	        ".valueentry {\n"
	        "	font-size: 10px;\n"
	        "	padding-left: 2px;\n"
	        "	color: #905d14;\n"
	        "	border-bottom: 1px dashed #f6c074;\n"
	        "}\n"
	        ".credits {\n"
	        "	font-size: 12px;\n"
	        "	font-weight: bold;\n"
	        "}\n"
	        ".maintable {\n"
	        "	border-style: solid;\n"
	        "	border-color: #0b4b5b;\n"
	        "	border-width: 1px;\n"
	        "}\n"
	        "</style>\n"
	        "</head>\n"
	        "<body><table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" class=\"maintable\">\n"
	       );
}

void om_html_print_footer(FILE *fp) {
	fprintf(fp, "</table></body></html>\n");
}

void om_html_print_title(FILE *fp, char *title) {
	fprintf(fp, "<tr><td align=\"center\" class=\"title\" colspan=\"3\"><a name=\"%s\"></a>", title);
	om_html_entities(fp, title);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_subtitle(FILE *fp, char *subtitle) {
	fprintf(fp, "<tr><td align=\"center\" class=\"subtitle\" colspan=\"3\">");
	om_html_entities(fp, subtitle);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkey_info(FILE *fp, char *key, int val) {
	fprintf(fp, "<tr><td align=\"left\" colspan=\"3\" class=\"info\">");
	om_html_entities(fp, key);
	fprintf(fp, " %d", val);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_keykey_entry(FILE *fp, char *key1, char *key2, int num) {
	fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	fprintf(fp, "%d)", num);
	fprintf(fp, "<td align=\"left\" class=\"valueentry\">");
	om_html_entities(fp, key1);
	fprintf(fp, "</td><td align=\"left\" class=\"keyentry\">");
	
	if (strncmp(key2, "http://", 7) || !strncmp(key2, "https://", 8) || !strncmp(key2, "ftp://", 6)) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", key2);
		om_html_entities(fp, key2);
		fprintf(fp, "</a>");
	} else {
		om_html_entities(fp, key2);
	}
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkey_entry(FILE *fp, char *key, int val, char *link,
                                int num) {
	fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	fprintf(fp, "%d)", num);
	fprintf(fp, "<td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d", val);
	fprintf(fp, "</td><td align=\"left\" class=\"keyentry\">");
	if (link != NULL) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", link);
		om_html_entities(fp, key);
		fprintf(fp, "</a>");
	} else if (!strncmp(key, "http://", 7) || !strncmp(key, "https://", 8) || !strncmp(key, "ftp://", 6)) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", key);
		om_html_entities(fp, key);
		fprintf(fp, "</a>");
	} else {
		om_html_entities(fp, key);
	}
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_bar(FILE *fp, int l, char *leftclass, char *rightclass) {
	fprintf(fp, "<table cellpadding=\"0\" cellspacing=\"0\" width=\"400\" border=\"0\">\n");
	fprintf(fp, "<tr><td align=\"center\" class=\"%s\" width=\"%d%%\">%s</td>\n", leftclass, l, l ? "&nbsp;" : "");
	fprintf(fp, "<td align=\"center\" class=\"%s\" width=\"%d%%\">%s</td></tr>\n", rightclass, 100-l, (l!=100) ? "&nbsp;" : "");
	fprintf(fp, "</table>\n");
}

void om_html_print_numkeybar_entry(FILE *fp, char *key, int max, int tot, int this) {
	int l, weekend;
	float p;

	if (tot == 0) tot++;
	if (max == 0) max++;
	l = ((float)(100*this))/max;
	p = ((float)(100*this))/tot;
	weekend = vi_is_weekend(key);

	if (weekend)
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentrywe\">");
	else
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	om_html_entities(fp, key);
	fprintf(fp, "&nbsp;&nbsp;&nbsp;</td><td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d (%02.1f%%)", this, p);
	fprintf(fp, "</td><td align=\"left\" class=\"bar\">");
	om_html_print_bar(fp, l, "barfill", "barempty");
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkeycomparativebar_entry(FILE *fp, char *key, int tot, int this) {
	int l, weekend;
	float p;

	if (tot == 0) tot++;
	p = ((float)(100*this))/tot;
	l = (int) p;
	weekend = vi_is_weekend(key);

	if (weekend)
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentrywe\">");
	else
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	om_html_entities(fp, key);
	fprintf(fp, "&nbsp;&nbsp;&nbsp;</td><td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d (%02.1f%%)", this, p);
	fprintf(fp, "</td><td align=\"left\" class=\"bar\">");
	om_html_print_bar(fp, l, "barleft", "barright");
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_bidimentional_map(FILE *fp, int xlen, int ylen,
                                     char **xlabel, char **ylabel, int *value) {
	int x, y, l, max = 0;

	/* Get the max value */
	l = xlen*ylen;
	for (x = 0; x < l; x++)
		if (max < value[x])
			max = value[x];
	if (max == 0) max++; /* avoid division by zero */
	/* print the map */
	fprintf(fp, "<tr><td colspan=\"3\" align=\"center\">");
	fprintf(fp, "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">");
	for (y = 0; y < ylen; y++) {
		fprintf(fp, "<tr>");
		fprintf(fp, "<td class=\"valueentry\">%s</td>", ylabel[y]);
		for (x = 0; x < xlen; x++) {
			int r, g, b;
			int val = value[(y*xlen)+x];

			r = (0xAA*val)/max;
			g = (0xBB*val)/max;
			b = (0xFF*val)/max;
			fprintf(fp, "<td style=\"background-color: #%02X%02X%02X;\" title=\"%d\">&nbsp;</td>\n", r, g, b, val);
		}
		fprintf(fp, "</tr>\n");
	}
	fprintf(fp, "<tr><td>&nbsp;</td>");
	for (x = 0; x < xlen; x++) {
		fprintf(fp, "<td class=\"keyentry\">%s</td>", xlabel[x]);
	}
	fprintf(fp, "</tr></table></td></tr>");
}

void om_html_print_hline(FILE *fp) {
	fprintf(fp, "<tr><td colspan=\"3\">&nbsp;</td></tr>");
}

void om_html_print_credits(FILE *fp) {
	fprintf(fp, "<tr><td colspan=\"3\" align=\"center\" class=\"credits\">Statistics generated with <a href=\"http://www.hping.org/visitors\">VISITED Proxy Log Analyzer</a> version %s\n</td></tr>", VI_VERSION_STR);
}

void om_html_print_report_link(FILE *fp, char *report) {
	fprintf(fp, "<tr><td align=\"left\" class=\"reportlink\" colspan=\"3\"><a href=\"#%s\">", report);
	om_html_entities(fp, report);
	fprintf(fp, "</a></td></tr>\n");
	return;
}

struct outputmodule OutputModuleHtml = {
	om_html_print_header,
	om_html_print_footer,
	om_html_print_title,
	om_html_print_subtitle,
	om_html_print_numkey_info,
	om_html_print_keykey_entry,
	om_html_print_numkey_entry,
	om_html_print_numkeybar_entry,
	om_html_print_numkeycomparativebar_entry,
	om_html_print_bidimentional_map,
	om_html_print_hline,
	om_html_print_credits,
	om_html_print_report_link,
};


/* ---------------------------------- output -------------------------------- */
void vi_print_statistics(struct vih *vih) {
	time_t elapsed = vih->endt - vih->startt;

	if (elapsed == 0) elapsed++;
	fprintf(stderr, "--\n%d lines processed in %ld seconds\n"
	        "%d invalid lines, %d blacklisted referers\n",
	        vih->processed, (long) elapsed,
	        vih->invalid, vih->blacklisted);
}

void vi_print_hours_report(FILE *fp, struct vih *vih) {
	int i, max_hits = 0, tot_hits = 0;
	long max_size = 0, tot_size = 0;
	for (i = 0; i < 24; i++) {
		if (vih->hour_hits[i] > max_hits)
			max_hits = vih->hour_hits[i];
		tot_hits += vih->hour_hits[i];
	}
	Output->print_title(fp, "Hours distribution");
	Output->print_subtitle(fp, "Percentage of hits in every hour of the day");
	for (i = 0; i < 24; i++) {
		char buf[8];
		sprintf(buf, "%02d", i);
		Output->print_numkeybar_entry(fp, buf, max_hits, tot_hits, vih->hour_hits[i]);
	}
	for (i = 0; i < 24; i++) {
		if (vih->hour_size[i] > max_size)
			max_size = vih->hour_size[i];
		tot_size += vih->hour_size[i];
	}
	Output->print_title(fp, "Hours distribution");
	Output->print_subtitle(fp, "Percentage of traffic in every hour of the day");
	for (i = 0; i < 24; i++) {
		char buf[8];
		sprintf(buf, "%02d", i);
		Output->print_numkeybar_entry(fp, buf, max_size, tot_size, vih->hour_size[i]);
	}
}

void vi_print_weekdays_report(FILE *fp, struct vih *vih) {
	int i, max_hits = 0, tot_hits = 0;
	long max_size = 0, tot_size = 0;
	for (i = 0; i < 7; i++) {
		if (vih->weekday_hits[i] > max_hits)
			max_hits = vih->weekday_hits[i];
		tot_hits += vih->weekday_hits[i];
	}
	Output->print_title(fp, "Weekdays distribution");
	Output->print_subtitle(fp, "Percentage of hits in every day of the week");
	for (i = 0; i < 7; i++) {
		Output->print_numkeybar_entry(fp, vi_wdname[i], max_hits, tot_hits, vih->weekday_hits[i]);
	}
	for (i = 0; i < 7; i++) {
		if (vih->weekday_size[i] > max_size)
			max_size = vih->weekday_size[i];
		tot_size += vih->weekday_size[i];
	}
	Output->print_title(fp, "Weekdays distribution");
	Output->print_subtitle(fp, "Percentage of traffic in every day of the week");
	for (i = 0; i < 7; i++) {
		Output->print_numkeybar_entry(fp, vi_wdname[i], max_size, tot_size, vih->weekday_size[i]);
	}
}

/* Generic function for qsort(3) called to sort a table.
 * this function is actually only used by the following wrappers. */
int qsort_cmp_dates_generic(const void *a, const void *b, int off, int mul) {
	time_t ta, tb;
	void **A = (void**) a;
	void **B = (void**) b;
	char *dateA = (char*) *(A+off);
	char *dateB = (char*) *(B+off);

	ta = parse_date(dateA, NULL);
	tb = parse_date(dateB, NULL);
	if (ta == (time_t)-1 && tb == (time_t)-1) return 0;
	if (ta == (time_t)-1) return 1*mul;
	if (tb == (time_t)-1) return -1*mul;
	if (ta > tb) return 1*mul;
	if (ta < tb) return -1*mul;
	return 0;
}

/* Compare dates in the log format: hashtable key part version */
int qsort_cmp_dates_key(const void *a, const void *b) {
	return qsort_cmp_dates_generic(a, b, 0, 1);
}

/* Compare dates (only the month/year part) in the log format:
 * hashtable key part version */
int qsort_cmp_months_key(const void *a, const void *b) {
	int ret;
	char dateA[VI_DATE_MAX];
	char dateB[VI_DATE_MAX];
	void *savedA, *savedB; /* backups of the original pointers */
	void **A = (void**) a;
	void **B = (void**) b;

	/* We use an hack here, in order to call qsort_cmp_dates_generic
	 * even in this case, we substitute the hashtable entries
	 * with versions of the strings prefixed with "01", so they
	 * will be parseble by parse_date().
	 * In pratice for "May/2004" we instead put "01/May/2004" and so on. */
	savedA = *A;
	savedB = *B;
	dateA[0] = dateB[0] = '0';
	dateA[1] = dateB[1] = '1';
	dateA[2] = dateB[2] = '/';
	dateA[3] = dateB[3] = '\0';
	vi_strlcat(dateA, (char*)*A, VI_DATE_MAX);
	vi_strlcat(dateB, (char*)*B, VI_DATE_MAX);
	*A = dateA;
	*B = dateB;
	ret = qsort_cmp_dates_generic(a, b, 0, 1);
	/* Restore */
	*A = savedA;
	*B = savedB;
	return ret;
}

/* Compare dates in the log format: hashtable value part version.
 * this sorts in reverse order, more recent dates first. */
int qsort_cmp_dates_value(const void *a, const void *b) {
	return qsort_cmp_dates_generic(a, b, 1, -1);
}

int qsort_cmp_long_value(const void *a, const void *b) {
	void **A = (void**) a;
	void **B = (void**) b;
	long la = (long) *(A+1);
	long lb = (long) *(B+1);
	if (la > lb) return -1;
	if (lb > la) return 1;
	return 0;
}

int qsort_cmp_time_value(const void *a, const void *b) {
	void **A = (void**) a;
	void **B = (void**) b;
	time_t ta = (time_t) *(A+1);
	time_t tb = (time_t) *(B+1);
	if (ta > tb) return -1;
	if (tb > ta) return 1;
	return 0;
}

void vi_print_hits_report(FILE *fp, struct vih *vih) {
	int days = ht_used(&vih->date), i, tot = 0, max = 0;
	int months;
	void **table;

	Output->print_title(fp, "Daily hits");
	Output->print_subtitle(fp, "Hits in each day");
	Output->print_numkey_info(fp, "Number of users",
	                          ht_used(&vih->users_hits));
	Output->print_numkey_info(fp, "Different days in logfile",
	                          ht_used(&vih->date));

	if ((table = ht_get_array(&vih->date)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_hits_report()\n");
		return;
	}
	qsort(table, days, sizeof(void*)*2, qsort_cmp_dates_key);
	for (i = 0; i < days; i++) {
		long value = (long) table[(i*2)+1];
		if (value > max)
			max = value;
		tot += value;
	}
	for (i = 0; i < days; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
	Output->print_hline(fp);

	/* Monthly  hits*/
	if (Config_process_monthly_hits == 0) return;
	tot = max = 0;
	months = ht_used(&vih->month_hits);
	Output->print_title(fp, "Monthly hits");
	Output->print_subtitle(fp, "Hits in each month in KB");
	Output->print_numkey_info(fp, "Number of users",
	                          ht_used(&vih->users_hits));
	Output->print_numkey_info(fp, "Different months in logfile",
	                          ht_used(&vih->month_hits));

	if ((table = ht_get_array(&vih->month_hits)) == NULL) {
		fprintf(stderr, "Out of memory in print_hits_report()\n");
		return;
	}
	qsort(table, months, sizeof(void*)*2, qsort_cmp_months_key);
	for (i = 0; i < months; i++) {
		long value = (long) table[(i*2)+1];
		if (value > max)
			max = value;
		tot += value;
	}
	for (i = 0; i < months; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);

	/* Monthly size */
	if (Config_process_monthly_hits == 0) return;
	tot = max = 0;
	months = ht_used(&vih->month_size);
	Output->print_title(fp, "Monthly size");
	Output->print_subtitle(fp, "Size in each month in KB");
	Output->print_numkey_info(fp, "Number of users",
	                          ht_used(&vih->users_size));
	Output->print_numkey_info(fp, "Different months in logfile",
	                          ht_used(&vih->month_size));

	if ((table = ht_get_array(&vih->month_size)) == NULL) {
		fprintf(stderr, "Out of memory in print_hits_report()\n");
		return;
	}
	qsort(table, months, sizeof(void*)*2, qsort_cmp_months_key);
	for (i = 0; i < months; i++) {
		long value = (long) table[(i*2)+1];
		if (value > max)
			max = value;
		tot += value;
	}
	for (i = 0; i < months; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
}

void vi_print_generic_keyval_report(FILE *fp, char *title, char *subtitle,
                                    char *info, int maxlines,
                                    struct hashtable *ht,
                                    int(*compar)(const void *, const void *)) {
	int items = ht_used(ht), i;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out of memory in print_generic_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		if (i >= maxlines) break;
		if (key[0] == '\0')
			Output->print_numkey_entry(fp, "none", value, NULL,
			                           i+1);
		else
			Output->print_numkey_entry(fp, key, value, NULL, i+1);
	}
	free(table);
}

void vi_print_generic_keyvalbar_report(FILE *fp, char *title, char *subtitle,
                                       char *info, int maxlines,
                                       struct hashtable *ht,
                                       int(*compar)(const void *, const void *)) {
	int items = ht_used(ht), i, max = 0, tot = 0;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out of memory in print_generic_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		long value = (long) table[(i*2)+1];
		tot += value;
		if (value > max) max = value;
	}
	for (i = 0; i < items; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		if (i >= maxlines) break;
		if (key[0] == '\0')
			Output->print_numkeybar_entry(fp, "none", max, tot, value);
		else
			Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
}

void vi_print_pages_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyval_report(
	    fp,
	    "Pages by hits",
	    "Page requests ordered by hits",
	    "Different pages requested",
	    Config_max_pages,
	    &vih->pages_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyval_report(
	    fp,
	    "Pages by size",
	    "Page requests ordered by size in KB",
	    "Different pages requested",
	    Config_max_pages,
	    &vih->pages_size,
	    qsort_cmp_long_value);
}

void vi_print_error404_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyval_report(
	    fp,
	    "404 Errors",
	    "Requests for missing documents",
	    "Different missing documents requested",
	    Config_max_error404,
	    &vih->error404,
	    qsort_cmp_long_value);
}

void vi_print_types_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "File types by hits",
	    "Requested file types ordered by hits",
	    "Different file types requested",
	    Config_max_types,
	    &vih->types_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "File types by size",
	    "Requested file types ordered by size in KB",
	    "Different file types requested",
	    Config_max_types,
	    &vih->types_size,
	    qsort_cmp_long_value);
}

void vi_print_codes_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Codes by hits",
	    "HTTP codes ordered by hits",
	    "Different HTTP codes",
	    Config_max_codes,
	    &vih->codes_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Codes by size",
	    "HTTP codes ordered by size in KB",
	    "Different HTTP codes",
	    Config_max_codes,
	    &vih->codes_size,
	    qsort_cmp_long_value);
}

void vi_print_sites_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Sites by hits",
	    "Sites sorted by hits",
	    "Total number of sites",
	    Config_max_sites,
	    &vih->sites_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Sites by size",
	    "Sites sorted by size in KB",
	    "Total number of sites",
	    Config_max_sites,
	    &vih->sites_size,
	    qsort_cmp_long_value);
}

void vi_print_hosts_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Hosts by hits",
	    "Hosts sorted by hits",
	    "Total number of hosts",
	    Config_max_hosts,
	    &vih->hosts_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Hosts by size",
	    "Hosts sorted by size in KB",
	    "Total number of hosts",
	    Config_max_hosts,
	    &vih->hosts_size,
	    qsort_cmp_long_value);
}

void vi_print_users_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Users by hits",
	    "Users sorted by hits",
	    "Total number of users",
	    Config_max_hosts,
	    &vih->users_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Users by size",
	    "Users sorted by size in KB",
	    "Total number of users",
	    Config_max_hosts,
	    &vih->users_size,
	    qsort_cmp_long_value);
}

void vi_print_verbs_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Methods by hits",
	    "HTTP methods sorted by hits",
	    "Total number of methods",
	    100,
	    &vih->verbs_hits,
	    qsort_cmp_long_value);
	vi_print_generic_keyvalbar_report(
	    fp,
	    "Methods by size",
	    "HTTP methods sorted by size in KB",
	    "Total number of methods",
	    100,
	    &vih->verbs_size,
	    qsort_cmp_long_value);
}

/* Print a generic report where the two report items are strings
 * (usually url and date). Used to print the 'googled' and 'referers age'
 * reports. */
void vi_print_generic_keytime_report(FILE *fp, char *title, char *subtitle,
                                     char *info, int maxlines,
                                     struct hashtable *ht,
                                     int(*compar)(const void *, const void *)) {
	int items = ht_used(ht), i;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_generic_keytime_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		struct tm *tm;
		char ftime[1024];
		char *url = table[i*2];
		time_t time = (time_t) table[(i*2)+1];
		if (i >= maxlines) break;
		tm = localtime(&time);
		if (tm) {
			ftime[0] = '\0';
			strftime(ftime, 1024, "%d/%b/%Y", tm);
			Output->print_keykey_entry(fp, ftime,
			                           (url[0] == '\0') ? "none" : url, i+1);
		}
	}
	free(table);
}

void vi_print_information_report(FILE *fp, struct vih *vih) {
	char buf[VI_LINE_MAX];
	time_t now = time(NULL);
	snprintf(buf, VI_LINE_MAX, "Generated: %s", ctime(&now));
	Output->print_title(fp, "General information");
	Output->print_subtitle(fp, "Information about analyzed log files");
	Output->print_subtitle(fp, buf);
	Output->print_numkey_info(fp, "Number of entries processed", vih->processed);
	Output->print_numkey_info(fp, "Number of invalid entries", vih->invalid);
	Output->print_numkey_info(fp, "Processing time in seconds", (vih->endt)-(vih->startt));
}

void vi_print_report_links(FILE *fp) {
	void *l[] = {
		"Pages by hits", NULL,
		"Pages by size", NULL,
		"Sites by hits", &Config_process_sites,
		"Sites by size", &Config_process_sites,
		"File types by hits", &Config_process_types,
		"File types by size", &Config_process_types,
		"Users by hits", &Config_process_users,
		"Users by size", &Config_process_users,
		"Hosts by hits", &Config_process_hosts,
		"Hosts by size", &Config_process_hosts,
		"Codes by hits", &Config_process_codes,
		"Codes by size", &Config_process_codes,
		"Methods by hits", &Config_process_verbs,
		"Methods by size", &Config_process_verbs,
		"404 Errors", &Config_process_error404,
		"Weekday distribution", NULL,
		"Hours distribution", NULL,
		"Daily hits", NULL,
		"Monthly hits", NULL,
		"Weekday-Hour combined map", &Config_process_weekdayhour_map,
		"Month-Day combined map", &Config_process_monthday_map,
	};
	unsigned int i, num = 0;

	Output->print_title(fp, "Generated reports");
	Output->print_subtitle(fp, "Click on the report name you want to see");
	for (i = 0; i < sizeof(l)/sizeof(void*); i += 2) {
		int active = l[i+1] == NULL ? 1 : *((int*)l[i+1]);
		if (active) num++;
	}
	Output->print_numkey_info(fp, "Number of reports generated", num);
	for (i = 0; i < sizeof(l)/sizeof(void*); i += 2) {
		int active = l[i+1] == NULL ? 1 : *((int*)l[i+1]);
		if (active)
			Output->print_report_link(fp, (char*)l[i]);
	}
}

void vi_print_weekdayhour_map_report(FILE *fp, struct vih *vih) {
	char *xlabel[24] = {
		"00", "01", "02", "03", "04", "05", "06", "07",
		"08", "09", "10", "11", "12", "13", "14", "15",
		"16", "17", "18", "19", "20", "21", "22", "23"
	};
	char **ylabel = vi_wdname;
	int j, minj = 0, maxj = 0;
	int *hw = (int*) vih->weekdayhour_hits;
	char buf[VI_LINE_MAX];

	/* Check indexes of minimum and maximum in the array. */
	for (j = 0; j < 24*7; j++) {
		if (hw[j] > hw[maxj])
			maxj = j;
		if (hw[j] < hw[minj])
			minj = j;
	}

	Output->print_title(fp, "Weekday-Hour combined map");
	Output->print_subtitle(fp, "Brighter means higher level of hits");
	snprintf(buf, VI_LINE_MAX, "Hour with max traffic starting at %s %s:00 with hits",
	         ylabel[maxj/24], xlabel[maxj%24]);
	Output->print_numkey_info(fp, buf, hw[maxj]);
	snprintf(buf, VI_LINE_MAX, "Hour with min traffic starting at %s %s:00 with hits",
	         ylabel[minj/24], xlabel[minj%24]);
	Output->print_numkey_info(fp, buf, hw[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 24, 7, xlabel, ylabel, hw);

	/* do sizes now */
	hw = (int*) vih->weekdayhour_size;
	minj = 0, maxj = 0;

	/* Check indexes of minimum and maximum in the array. */
	for (j = 0; j < 24*7; j++) {
		if (hw[j] > hw[maxj])
			maxj = j;
		if (hw[j] < hw[minj])
			minj = j;
	}

	Output->print_title(fp, "Weekday-Hour combined map");
	Output->print_subtitle(fp, "Brighter means higher level of traffic");
	snprintf(buf, VI_LINE_MAX, "Hour with max traffic starting at %s %s:00 with size",
	         ylabel[maxj/24], xlabel[maxj%24]);
	Output->print_numkey_info(fp, buf, hw[maxj]);
	snprintf(buf, VI_LINE_MAX, "Hour with min traffic starting at %s %s:00 with size",
	         ylabel[minj/24], xlabel[minj%24]);
	Output->print_numkey_info(fp, buf, hw[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 24, 7, xlabel, ylabel, hw);
}

void vi_print_monthday_map_report(FILE *fp, struct vih *vih) {
	char *xlabel[31] = {
		"01", "02", "03", "04", "05", "06", "07", "08",
		"09", "10", "11", "12", "13", "14", "15", "16",
		"17", "18", "19", "20", "21", "22", "23", "24",
		"25", "26", "27", "28", "29", "30", "31"
	};
	char *ylabel[12] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};
	int j, minj = 0, maxj = 0;
	int *md = (int*) vih->monthday_hits;
	char buf[VI_LINE_MAX];

	/* Check indexes of minimum and maximum in the array. */
	for (j = 0; j < 12*31; j++) {
		if (md[j] > md[maxj])
			maxj = j;
		if (md[j] != 0 && (md[j] < md[minj] || md[minj] == 0))
			minj = j;
	}

	Output->print_title(fp, "Month-Day combined map");
	Output->print_subtitle(fp, "Brighter means higher level of hits");
	snprintf(buf, VI_LINE_MAX, "Day with max traffic is %s %s with hits",
	         ylabel[maxj/31], xlabel[maxj%31]);
	Output->print_numkey_info(fp, buf, md[maxj]);
	snprintf(buf, VI_LINE_MAX, "Day with min traffic is %s %s with hits",
	         ylabel[minj/31], xlabel[minj%31]);
	Output->print_numkey_info(fp, buf, md[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 31, 12, xlabel, ylabel, md);

	/* do sizes now */
	md = (int*) vih->monthday_size;
	minj = 0, maxj = 0;
	
	/* Check indexes of minimum and maximum in the array. */
	for (j = 0; j < 12*31; j++) {
		if (md[j] > md[maxj])
			maxj = j;
		if (md[j] != 0 && (md[j] < md[minj] || md[minj] == 0))
			minj = j;
	}

	Output->print_title(fp, "Month-Day combined map");
	Output->print_subtitle(fp, "Brighter means higher level of traffic");
	snprintf(buf, VI_LINE_MAX, "Day with max traffic is %s %s with size",
	         ylabel[maxj/31], xlabel[maxj%31]);
	Output->print_numkey_info(fp, buf, md[maxj]);
	snprintf(buf, VI_LINE_MAX, "Day with min traffic is %s %s with size",
	         ylabel[minj/31], xlabel[minj%31]);
	Output->print_numkey_info(fp, buf, md[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 31, 12, xlabel, ylabel, md);
}

void vi_print_hline(FILE *fp) {
	Output->print_hline(fp);
}

void vi_print_credits(FILE *fp) {
	Output->print_credits(fp);
}

void vi_print_header(FILE *fp) {
	Output->print_header(fp);
}

void vi_print_footer(FILE *fp) {
	Output->print_footer(fp);
}

/* Generate the report writing it to the output file 'of'.
 * If op is NULL, output the report to standard output.
 * On success zero is returned. Otherwise the function returns
 * non-zero and set an error in the vih handler. */
int vi_print_report(char *of, struct vih *vih) {
	FILE *fp;

	if (of == NULL) {
		fp = stdout;
	} else {
		fp = fopen(of, "w");
		if (fp == NULL) {
			vi_set_error(vih, "Writing the report to '%s': %s",
			             of, strerror(errno));
			return 1;
		}
	}

	/* Report generation */
	vi_print_header(fp);
	vi_print_credits(fp);
	vi_print_hline(fp);
	vi_print_information_report(fp, vih);
	vi_print_hline(fp);
	vi_print_report_links(fp);
	vi_print_hline(fp);
	
	vi_print_pages_report(fp, vih);
	vi_print_hline(fp);
	if (Config_process_sites) {
		vi_print_sites_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_types) {
		vi_print_types_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_users) {
		vi_print_users_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_hosts) {
		vi_print_hosts_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_codes) {
		vi_print_codes_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_verbs) {
		vi_print_verbs_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_error404) {
		vi_print_error404_report(fp, vih);
		vi_print_hline(fp);
	}
	
	vi_print_weekdays_report(fp, vih);
	vi_print_hline(fp);
	vi_print_hours_report(fp, vih);
	vi_print_hline(fp);
	
	vi_print_hits_report(fp, vih);
	vi_print_hline(fp);

	if (Config_process_weekdayhour_map) {
		vi_print_weekdayhour_map_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_monthday_map) {
		vi_print_monthday_map_report(fp, vih);
		vi_print_hline(fp);
	}

	vi_print_credits(fp);
	vi_print_hline(fp);
	vi_print_footer(fp);
	if (of != NULL)
		fclose(fp);
	return 0;
}

/* -------------------------------- stream mode ----------------------------- */
void vi_stream_mode(struct vih *vih) {
	time_t lastupdate_t, lastreset_t, now_t;

	lastupdate_t = lastreset_t = time(NULL);
	while(1) {
		char buf[VI_LINE_MAX];

		if (fgets(buf, VI_LINE_MAX, stdin) == NULL) {
			vi_sleep(1);
			continue;
		}
		if (vi_process_line(vih, buf)) {
			fprintf(stderr, "%s\n", vi_get_error(vih));
		}
		now_t = time(NULL);
		/* update */
		if ((now_t - lastupdate_t) >= Config_update_every) {
			lastupdate_t = now_t;
			if (vi_print_report(Config_output_file, vih)) {
				fprintf(stderr, "%s\n", vi_get_error(vih));
			}
		}
		/* reset */
		if (Config_reset_every &&
		        ((now_t - lastreset_t) >= Config_reset_every)) {
			lastreset_t = now_t;
			vi_reset(vih);
		}
	}
}

/* ----------------------------------- main --------------------------------- */

/* command line switche IDs */
enum { OPT_USERS, OPT_MAXPAGES, OPT_MAXTYPES, OPT_CODES, OPT_ALL, OPT_MAXLINES, OPT_SITES, OPT_TYPES, OPT_HOSTS, OPT_MAXHOSTS, OPT_OUTPUT, OPT_VERSION, OPT_HELP, OPT_PREFIX, OPT_MAXCODES, OPT_MAXSITES, OPT_WEEKDAYHOUR_MAP, OPT_MONTHDAY_MAP, OPT_TAIL, OPT_STREAM, OPT_OUTPUTFILE, OPT_UPDATEEVERY, OPT_RESETEVERY, OPT_ERROR404, OPT_MAXERROR404, OPT_TIMEDELTA, OPT_GREP, OPT_EXCLUDE, OPT_IGNORE404, OPT_DEBUG};

/* command line switches definition:
 * the rule with short options is to take upper case the
 * 'special' options (the option a normal user should not use) */
static struct ago_optlist visited_optlist[] = {
	{ 'A',  "all",			OPT_ALL,		AGO_NOARG},
	{ 'U',	"users",		OPT_USERS,		AGO_NOARG},
	{ 'W',  "weekday-hour-map",	OPT_WEEKDAYHOUR_MAP,	AGO_NOARG},
	{ 'M',  "month-day-map",	OPT_MONTHDAY_MAP,	AGO_NOARG},
	{ 'S',  "sites",		OPT_SITES,	AGO_NOARG},
	{ 'T',  "types",		OPT_TYPES,		AGO_NOARG},
	{ 'E',  "error404",		OPT_ERROR404,		AGO_NOARG},
	{ 'H',  "hosts",		OPT_HOSTS,		AGO_NOARG},
	{ 'C',  "codes",		OPT_HOSTS,		AGO_NOARG},
	{ 'V',  "verbs",		OPT_HOSTS,		AGO_NOARG},
	{ '\0', "stream",		OPT_STREAM,		AGO_NOARG},
	{ '\0', "update-every",		OPT_UPDATEEVERY,	AGO_NEEDARG},
	{ '\0',	"reset-every",		OPT_RESETEVERY,		AGO_NEEDARG},
	{ 'f',	"output-file",		OPT_OUTPUTFILE,		AGO_NEEDARG},
	{ 'm',	"max-lines",		OPT_MAXLINES,		AGO_NEEDARG},
	{ '\0',	"max-hosts",		OPT_MAXHOSTS,	AGO_NEEDARG},
	{ '\0',	"max-pages",		OPT_MAXPAGES,		AGO_NEEDARG},
	{ '\0',	"max-codes",		OPT_MAXCODES,		AGO_NEEDARG},
	{ '\0',	"max-error404",		OPT_MAXERROR404,	AGO_NEEDARG},
	{ '\0',	"max-types",	OPT_MAXTYPES,	AGO_NEEDARG},
	{ '\0',	"max-sites",		OPT_MAXSITES,		AGO_NEEDARG},
	{ 'G',  "grep",                 OPT_GREP,               AGO_NEEDARG},
	{ 'X',  "exclude",              OPT_EXCLUDE,            AGO_NEEDARG},
	{ 'P',  "prefix",		OPT_PREFIX,		AGO_NEEDARG},
	{ 'o',  "output",		OPT_OUTPUT,		AGO_NEEDARG},
	{ 'v',  "version",		OPT_VERSION,		AGO_NOARG},
	{ '\0', "tail",			OPT_TAIL,		AGO_NOARG},
	{ '\0', "time-delta",		OPT_TIMEDELTA,		AGO_NEEDARG},
	{ '\0', "ignore-404",           OPT_IGNORE404,          AGO_NOARG},
	{ 'd',	"debug",		OPT_DEBUG,		AGO_NOARG},
	{ 'h',	"help",			OPT_HELP,		AGO_NOARG},
	AGO_LIST_TERM
};

void visited_show_help(void) {
	int i;

	printf("Usage: visited [options] <filename> [<filename> ...]\n");
	printf("Available options:\n");
	for (i = 0; visited_optlist[i].ao_long != NULL; i++) {
		if (visited_optlist[i].ao_short != '\0') {
			printf("  -%c ", visited_optlist[i].ao_short);
		} else {
			printf("     ");
		}
		printf("--%-30s %s\n",
		       visited_optlist[i].ao_long,
		       (visited_optlist[i].ao_flags & AGO_NEEDARG) ?
		       "<argument>" : "");
	}
	printf("Visited is Copyright(C) 2011 Camilo E. Hidalgo Estevez <camilohe@gmail.com>\n"
	       "Visited is based on Visitors, for more info visit http://www.hping.org/visitors\n"
	       "Visitors is Copyright(C) 2004-2006 Salvatore Sanfilippo <antirez@invece.org>\n");
}

int main(int argc, char **argv) {
	int i, o;
	struct vih *vih;
	char *filenames[VI_FILENAMES_MAX];
	int filenamec = 0;

	/* Handle command line options */
	while((o = antigetopt(argc, argv, visited_optlist)) != AGO_EOF) {
		switch(o) {
		case AGO_UNKNOWN:
		case AGO_REQARG:
		case AGO_AMBIG:
			ago_gnu_error("visited", o);
			visited_show_help();
			exit(1);
			break;
		case OPT_HELP:
			visited_show_help();
			exit(0);
			break;
		case OPT_VERSION:
			printf("Visited %s\n", VI_VERSION_STR);
			exit(0);
		case OPT_MAXPAGES:
			Config_max_pages = atoi(ago_optarg);
			break;
		case OPT_MAXTYPES:
			Config_max_types = atoi(ago_optarg);
			break;
		case OPT_MAXHOSTS:
			Config_max_hosts = atoi(ago_optarg);
			break;
		case OPT_MAXERROR404:
			Config_max_error404 = atoi(ago_optarg);
			break;
		case OPT_MAXCODES:
			Config_max_codes = atoi(ago_optarg);
			break;
		case OPT_MAXSITES:
			Config_max_sites = atoi(ago_optarg);
			break;
		case OPT_SITES:
			Config_process_sites = 1;
			break;
		case OPT_ERROR404:
			Config_process_error404 = 1;
			break;
		case OPT_TYPES:
			Config_process_types = 1;
			break;
		case OPT_HOSTS:
			Config_process_hosts = 1;
			break;
		case OPT_CODES:
			Config_process_codes = 1;
			break;
		case OPT_USERS:
			Config_process_users = 1;
			break;
		case OPT_ALL:
			Config_process_codes = 1;
			Config_process_weekdayhour_map = 1;
			Config_process_monthday_map = 1;
			Config_process_sites = 1;
			Config_process_error404 = 1;
			Config_process_types = 1;
			Config_process_users = 1;
			Config_process_hosts = 1;
			Config_process_verbs = 1;
			break;
		case OPT_PREFIX:
			if (Config_prefix_num < VI_PREFIXES_MAX) {
				Config_prefix[Config_prefix_num].str = ago_optarg;
				Config_prefix[Config_prefix_num].len = strlen(ago_optarg);
				Config_prefix_num++;
			} else {
				fprintf(stderr, "Error: too many prefixes specified\n");
				exit(1);
			}
			break;
		case OPT_MAXLINES: {
			int aux = atoi(ago_optarg);
			Config_max_requests = aux;
			Config_max_pages = aux;
			Config_max_types = aux;
			Config_max_error404 = aux;
			Config_max_codes = aux;
			Config_max_hosts = aux;
			Config_max_sites = aux;
		}
		break;
		case OPT_OUTPUT:
			if (!strcasecmp(ago_optarg, "text"))
				Output = &OutputModuleText;
			else if (!strcasecmp(ago_optarg, "html"))
				Output = &OutputModuleHtml;
			else {
				fprintf(stderr, "Unknown output module '%s'\n",
				        ago_optarg);
				exit(1);
			}
			break;
		case OPT_TAIL:
			Config_tail_mode = 1;
			break;
		case OPT_WEEKDAYHOUR_MAP:
			Config_process_weekdayhour_map = 1;
			break;
		case OPT_MONTHDAY_MAP:
			Config_process_monthday_map = 1;
			break;
		case OPT_STREAM:
			Config_stream_mode = 1;
			break;
		case OPT_OUTPUTFILE:
			Config_output_file = ago_optarg;
			break;
		case OPT_UPDATEEVERY:
			Config_update_every = atoi(ago_optarg);
			break;
		case OPT_RESETEVERY:
			Config_reset_every = atoi(ago_optarg);
			break;
		case OPT_TIMEDELTA:
			Config_time_delta = atoi(ago_optarg);
			break;
		case OPT_GREP:
			ConfigAddGrepPattern(ago_optarg, VI_PATTERNTYPE_GREP);
			break;
		case OPT_EXCLUDE:
			ConfigAddGrepPattern(ago_optarg, VI_PATTERNTYPE_EXCLUDE);
			break;
		case OPT_IGNORE404:
			Config_ignore_404 = 1;
			break;
		case OPT_DEBUG:
			Config_debug = 1;
			break;
		case AGO_ALONE:
			if (filenamec < VI_FILENAMES_MAX)
				filenames[filenamec++] = ago_optarg;
			break;
		}
	}
	/* If the user specified the 'tail' mode, we
	 * just emulate a "tail -f" for the specified files. */
	if (Config_tail_mode) {
		vi_tail(filenamec, filenames);
		return 0;
	}
	/* Check if at least one file was specified */
	if (filenamec == 0 && !Config_stream_mode) {
		fprintf(stderr, "No logfile specified\n");
		visited_show_help();
		exit(1);
	}
	/* If stream-mode is enabled, --output-file should be specified. */
	if (Config_stream_mode && Config_output_file == NULL) {
		fprintf(stderr, "--stream requires --output-file\n");
		exit(1);
	}
	/* Set the default output module */
	if (Output == NULL)
		Output = &OutputModuleHtml;
	/* Change to "C" locale for date/time related functions */
	setlocale(LC_ALL, "C");
	/* Process all the log files specified. */
	vih = vi_new();
	for (i = 0; i < filenamec; i++) {
		if (vi_scan(vih, filenames[i])) {
			fprintf(stderr, "%s: %s\n", filenames[i], vi_get_error(vih));
			exit(1);
		}
	}
	if (vi_print_report(Config_output_file, vih)) {
		fprintf(stderr, "%s\n", vi_get_error(vih));
		exit(1);
	}
	if (Config_stream_mode) {
		vi_stream_mode(vih);
	}
	vi_print_statistics(vih);
	/* The following is commented in releases as to free the hashtable
	 * memory is very slow, it's better to just exit the program.
	 * Still it is important to be able to re-enable a good cleanup
	 * in order to run visitors against valgrind to check for memory
	 * leaks. */
	/* vi_free(vih); */
	return 0;
}
