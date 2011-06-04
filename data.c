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

	ts->emm      = ts_privsec_alloc();
	ts->last_emm = ts_privsec_alloc();

	ts->ecm      = ts_privsec_alloc();
	ts->last_ecm = ts_privsec_alloc();

	pidmap_clear(&ts->pidmap);

	// Key
	memset(&ts->key, 0, sizeof(ts->key));
	ts->key.csakey[0] = dvbcsa_key_alloc();
	ts->key.csakey[1] = dvbcsa_key_alloc();

	// CAMD
	memset(&ts->camd35, 0, sizeof(ts->camd35));
	ts->camd35.server_fd    = -1;
	ts->camd35.server_port  = 2233;
	ts->camd35.key          = &ts->key;
	strcpy(ts->camd35.user, "user");
	strcpy(ts->camd35.pass, "pass");

	// Config
	ts->debug_level = 0;
	ts->req_CA_sys  = CA_CONNAX;
	ts->emm_send    = 1;
	ts->pid_filter  = 0;

	ts->input.fd    = 0; // STDIN
	ts->input.type  = FILE_IO;

	ts->output.fd   = 1; // STDOUT
	ts->output.type = FILE_IO;
	ts->output.ttl  = 1;
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
	ts_privsec_free(&ts->ecm);
	ts_privsec_free(&ts->last_ecm);

	dvbcsa_key_free(ts->key.csakey[0]);
	dvbcsa_key_free(ts->key.csakey[1]);

	FREE(ts->input.fname);
	FREE(ts->output.fname);
}
