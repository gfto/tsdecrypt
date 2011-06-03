#ifndef DATA_H
#define DATA_H

#include "libts/tsfuncs.h"

struct ts {
	struct ts_pat		*pat, *curpat;
	struct ts_cat		*cat, *curcat;
	struct ts_pmt		*pmt, *curpmt;
	struct ts_privsec	*emm, *last_emm;
	struct ts_privsec	*ecm, *last_ecm;
	uint16_t			pmt_pid;
	uint16_t			service_id;
	uint16_t			emm_caid, emm_pid;
	uint16_t			ecm_caid, ecm_pid;
	uint16_t			ecm_counter;
	pidmap_t			pidmap;
};

struct ts *ts_alloc();
void ts_free(struct ts **pts);

void LOG_func(const char *msg);

void show_ts_pack(uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet);
void dump_ts_pack(uint16_t pid, uint8_t *ts_packet);

#endif
