/*
 * Data functions
 * Copyright (C) 2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "data.h"

void data_init(struct ts *ts) {
	memset(ts, 0, sizeof(struct ts));
	// Stream
	ts->pat	     = ts_pat_alloc();
	ts->curpat   = ts_pat_alloc();

	ts->cat      = ts_cat_alloc();
	ts->curcat   = ts_cat_alloc();

	ts->pmt      = ts_pmt_alloc();
	ts->curpmt   = ts_pmt_alloc();

	ts->sdt      = ts_sdt_alloc();
	ts->cursdt   = ts_sdt_alloc();

	ts->emm      = ts_privsec_alloc();
	ts->last_emm = ts_privsec_alloc();
	ts->tmp_emm  = ts_privsec_alloc();

	ts->ecm      = ts_privsec_alloc();
	ts->last_ecm = ts_privsec_alloc();
	ts->tmp_ecm  = ts_privsec_alloc();

	pidmap_clear(&ts->pidmap);
	pidmap_clear(&ts->cc);
	pidmap_clear(&ts->pid_seen);

	// Key
	memset(&ts->key, 0, sizeof(ts->key));
	ts->key.csakey[0] = dvbcsa_key_alloc();
	ts->key.csakey[1] = dvbcsa_key_alloc();

	ts->key.bs_csakey[0] = dvbcsa_bs_key_alloc();
	ts->key.bs_csakey[1] = dvbcsa_bs_key_alloc();

	gettimeofday(&ts->key.ts_keyset, NULL);

	// CAMD
	memset(&ts->camd35, 0, sizeof(ts->camd35));
	ts->camd35.server_fd    = -1;
	ts->camd35.server_port  = 2233;
	ts->camd35.key          = &ts->key;
	strcpy(ts->camd35.user, "user");
	strcpy(ts->camd35.pass, "pass");

	// Config
	ts->syslog_port = 514;

	ts->ts_discont  = 1;
	ts->ecm_cw_log  = 1;

	ts->debug_level = 0;
	ts->req_CA_sys  = CA_CONAX;
	ts->emm_send    = 0;
	ts->pid_filter  = 1;

	ts->emm_report_interval = 60;
	ts->emm_last_report     = time(NULL);

	ts->ecm_report_interval = 60;
	ts->ecm_last_report     = time(NULL);

	ts->cw_warn_sec = 20;
	ts->cw_last_warn= time(NULL);

	ts->input.fd    = 0; // STDIN
	ts->input.type  = FILE_IO;

	ts->output.fd   = 1; // STDOUT
	ts->output.type = FILE_IO;
	ts->output.ttl  = 1;

	ts->decode_buf  = cbuf_init((7 * dvbcsa_bs_batch_size() * 188) * 16, "decode"); // ~658Kb
	ts->write_buf   = cbuf_init((7 * dvbcsa_bs_batch_size() * 188) *  8, "write");  // ~324Kb
}

void data_free(struct ts *ts) {
	ts_pat_free(&ts->pat);
	ts_pat_free(&ts->curpat);
	ts_cat_free(&ts->cat);
	ts_cat_free(&ts->curcat);
	ts_pmt_free(&ts->pmt);
	ts_pmt_free(&ts->curpmt);
	ts_privsec_free(&ts->emm);
	ts_privsec_free(&ts->last_emm);
	ts_privsec_free(&ts->tmp_emm);
	ts_privsec_free(&ts->ecm);
	ts_privsec_free(&ts->last_ecm);
	ts_privsec_free(&ts->tmp_ecm);

	dvbcsa_key_free(ts->key.csakey[0]);
	dvbcsa_key_free(ts->key.csakey[1]);

	dvbcsa_bs_key_free(ts->key.bs_csakey[0]);
	dvbcsa_bs_key_free(ts->key.bs_csakey[1]);

	cbuf_free(&ts->decode_buf);
	cbuf_free(&ts->write_buf);

	FREE(ts->input.fname);
	FREE(ts->output.fname);
}
