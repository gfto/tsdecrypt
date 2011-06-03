#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "data.h"

struct ts *ts_alloc() {
	struct ts *ts = calloc(1, sizeof(struct ts));
	ts->pat	     = ts_pat_alloc();
	ts->curpat   = ts_pat_alloc();

	ts->cat      = ts_cat_alloc();
	ts->curcat   = ts_cat_alloc();

	ts->pmt      = ts_pmt_alloc();
	ts->curpmt   = ts_pmt_alloc();

	ts->emm      = ts_privsec_alloc();
	ts->last_emm = ts_privsec_alloc();

	ts->ecm      = ts_privsec_alloc();
	ts->last_ecm = ts_privsec_alloc();

	pidmap_clear(&ts->pidmap);

	return ts;
}

void ts_free(struct ts **pts) {
	struct ts *ts = *pts;
	if (ts) {
		ts_pat_free(&ts->pat);
		ts_pat_free(&ts->curpat);
		ts_cat_free(&ts->cat);
		ts_cat_free(&ts->curcat);
		ts_pmt_free(&ts->pmt);
		ts_pmt_free(&ts->curpmt);
		ts_privsec_free(&ts->emm);
		ts_privsec_free(&ts->last_emm);
		ts_privsec_free(&ts->ecm);
		ts_privsec_free(&ts->last_ecm);
		FREE(*pts);
	}
}

void LOG_func(const char *msg) {
	char date[64];
	struct tm tm;
	time_t now;
	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime(&now));
	fprintf(stderr, "%s | %s", date, msg);
}

extern int debug_level;
extern unsigned long ts_pack;
extern int ts_pack_shown;
extern uint8_t cur_cw[16];

void show_ts_pack(uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet) {
	char cw1_dump[8 * 6];
	char cw2_dump[8 * 6];
	if (debug_level >= 4) {
		if (ts_pack_shown)
			return;
		int stype = ts_packet_get_scrambled(ts_packet);
		ts_hex_dump_buf(cw1_dump, 8 * 6, cur_cw    , 8, 0);
		ts_hex_dump_buf(cw2_dump, 8 * 6, cur_cw + 8, 8, 0);
		fprintf(stderr, "@ %s %s %03x %5ld %7ld | %s   %s | %s\n",
			stype == 0 ? "------" :
			stype == 2 ? "even 0" :
			stype == 3 ? "odd  1" : "??????",
			wtf,
			pid,
			ts_pack, ts_pack * 188,
			cw1_dump, cw2_dump, extra ? extra : wtf);
	}
}

void dump_ts_pack(uint16_t pid, uint8_t *ts_packet) {
	if (pid == 0x010)		show_ts_pack(pid, "nit", NULL, ts_packet);
	else if (pid == 0x11)	show_ts_pack(pid, "sdt", NULL, ts_packet);
	else if (pid == 0x12)	show_ts_pack(pid, "epg", NULL, ts_packet);
	else					show_ts_pack(pid, "---", NULL, ts_packet);
}
