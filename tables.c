/*
 * Process PSI tables
 * Copyright (C) 2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */
#include <string.h>

#include "data.h"
#include "tables.h"
#include "camd.h"
#include "filter.h"

#include "libtsfuncs/tsfuncs.h"
#include "libfuncs/libfuncs.h"

extern void show_ts_pack(struct ts *ts, uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet);

#define handle_table_changes(TABLE) \
	do { \
		show_ts_pack(ts, pid, #TABLE, NULL, ts_packet); \
		ts->cur##TABLE = ts_##TABLE##_push_packet(ts->cur##TABLE, ts_packet); \
		if (!ts->cur##TABLE->initialized) \
			return;  \
		if (ts_##TABLE##_is_same(ts->TABLE, ts->cur##TABLE)) { \
			ts_##TABLE##_clear(ts->cur##TABLE); \
			return; \
		} \
		ts_##TABLE##_free(&ts->TABLE); \
		ts->TABLE = ts_##TABLE##_copy(ts->cur##TABLE); \
		ts_##TABLE##_clear(ts->cur##TABLE); \
		if (ts->debug_level >= 1) \
			ts_##TABLE##_dump(ts->TABLE); \
	} while(0)

void process_pat(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int i;
	int num_services = 0;
	uint16_t f_service = 0, f_pid = 0;
	if (pid != 0x00)
		return;

	handle_table_changes(pat);

	for (i=0;i<ts->pat->programs_num;i++) {
		struct ts_pat_program *prg = ts->pat->programs[i];
		if (prg->pid && prg->program != 0) {
			num_services++;
			ts->pmt_pid    = prg->pid;
			ts->service_id = prg->program;
			if (prg->program == ts->forced_service_id) {
				f_pid     = prg->pid;
				f_service = prg->program;
			}
		}
	}

	if (f_service && f_pid) {
		ts->pmt_pid    = f_pid;
		ts->service_id = f_service;
	}

	if (num_services > 1 && !f_service) {
		ts_LOGf("PAT | %d services exists. Consider using --input-service parameter.\n",
			num_services);
		for (i = 0; i < ts->pat->programs_num; i++) {
			struct ts_pat_program *prg = ts->pat->programs[i];
			if (prg->pid && prg->program != 0) {
				ts_LOGf("PAT | Service 0x%04x (%5d) with PMT PID %04x (%d)\n",
					prg->program, prg->program,
					prg->pid, prg->pid);
			}
		}
	}

	ts_LOGf("PAT | Using service 0x%04x (%d), PMT pid: %04x (%d)\n",
		ts->service_id, ts->service_id,
		ts->pmt_pid, ts->pmt_pid);

	if (num_services > 1) {
		ts_pat_clear(ts->genpat);
		ts->genpat = ts_pat_init(ts->genpat, ts->pat->section_header->ts_id_number);
		ts_pat_add_program(ts->genpat, ts->service_id, ts->pmt_pid);
	}
}

void process_cat(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (pid != 0x01)
		return;

	handle_table_changes(cat);

	if (ts->camd.constant_codeword)
		return;

	if (ts->forced_caid) {
		ts->emm_caid = ts->forced_caid;
		ts_get_emm_info_by_caid(ts->cat, ts->emm_caid, &ts->emm_pid);
	} else {
		ts_get_emm_info(ts->cat, ts->req_CA_sys, &ts->emm_caid, &ts->emm_pid);
	}

	if (ts->forced_emm_pid)
		ts_get_emm_info_by_pid(ts->cat, &ts->emm_caid, ts->forced_emm_pid);

	if (ts->emm_caid) {
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(ts->emm_caid));
		ts_LOGf("--- | EMM CAID: 0x%04x (%s)\n", ts->emm_caid, CA_sys);
		if (!ts->forced_emm_pid) {
			ts_LOGf("--- | EMM pid : 0x%04x (%s)\n", ts->emm_pid, CA_sys);
		} else {
			ts_LOGf("--- | EMM pid : 0x%04x (%s) (forced: 0x%04x)\n",
				ts->emm_pid, CA_sys, ts->forced_emm_pid);
			ts->emm_pid = ts->forced_emm_pid;
		}
	} else {
		ts_LOGf("*** | ERROR: Can't detect EMM pid.\n");
	}
}

// Copied from libtsfuncs with added logic to return more than one PID and to handle both req_CA_type && forced_caid
static int find_CA_descriptor(uint8_t *data, int data_len, enum CA_system req_CA_type, uint16_t forced_caid, uint16_t *CA_id, uint16_t *CA_pid, uint16_t *CA_pids, unsigned int *n_pids) {
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		data     += 2;
		data_len -= 2;
		if (tag == 9 && this_length >= 4) {
			uint16_t CA_ID = (data[0] << 8) | data[1];
			uint16_t CA_PID = ((data[2] & 0x1F) << 8) | data[3];
			bool ca_match = 0;
			if (forced_caid) {
				ca_match = forced_caid == CA_ID;
			} else {
				ca_match = ts_get_CA_sys(CA_ID) == req_CA_type;
			}
			if (ca_match) {
				*CA_id = CA_ID;
				*CA_pid = CA_PID;
				if (*n_pids < MAX_ECM_PIDS) {
					unsigned int i, exist = 0;
					for (i = 0; i < MAX_ECM_PIDS; i++) {
						if (CA_pids[i] == CA_PID) {
							exist = 1;
							break;
						}
					}
					if (!exist) {
						CA_pids[(*n_pids)++] = CA_PID;
					}
				}
			}
		}
		data_len -= this_length;
		data += this_length;
	}
	return 0;
}

// Copied from libtsfuncs with added logic to return more than one PID
int __ts_get_ecm_info(struct ts_pmt *pmt, enum CA_system req_CA_type, uint16_t forced_caid, uint16_t *CA_id, uint16_t *CA_pid, uint16_t *CA_pids, unsigned int *n_pids) {
	int i, result = find_CA_descriptor(pmt->program_info, pmt->program_info_size, req_CA_type, forced_caid, CA_id, CA_pid, CA_pids, n_pids);
	if (!result) {
		for(i=0;i<pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = pmt->streams[i];
			if (stream->ES_info) {
				result = find_CA_descriptor(stream->ES_info, stream->ES_info_size, req_CA_type, forced_caid, CA_id, CA_pid, CA_pids, n_pids);
				if (result)
					break;
			}
		}
	}
	return result;
}

void process_pmt(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int i;
	if (!pid || pid != ts->pmt_pid)
		return;

	// Mark PMT as valid and the received timestamp
	ts->last_pmt_ts = time(NULL);
	ts->have_valid_pmt = 1;

	handle_table_changes(pmt);

	pidmap_clear(&ts->pidmap);
	pidmap_set(&ts->pidmap, 0x0000); // PAT
	pidmap_set(&ts->pidmap, 0x0011); // SDT
	if (ts->nit_passthrough)
		pidmap_set(&ts->pidmap, 0x0010); // NIT
	if (ts->eit_passthrough)
		pidmap_set(&ts->pidmap, 0x0012); // EIT
	if (ts->tdt_passthrough)
		pidmap_set(&ts->pidmap, 0x0014); // TDT/TOT
	pidmap_set(&ts->pidmap, ts->pmt->ts_header.pid); // PMT PID
	pidmap_set(&ts->pidmap, ts->pmt->PCR_pid); // PCR
	for (i=0;i<ts->pmt->streams_num;i++) {
		struct ts_pmt_stream *stream = ts->pmt->streams[i];
		pidmap_set(&ts->pidmap, stream->pid); // Data
	}

	if (ts->camd.constant_codeword)
		return;

	// initialise used values to 0
	ts->ecm_caid = 0;
	ts->ecm_pid = 0;
	for (int j=0; j<MAX_ECM_PIDS; j++)
		ts->ecm_pids[j] = 0;
	// end initialising values
	ts->n_ecm_pids = 0;

	__ts_get_ecm_info(ts->pmt, ts->req_CA_sys, ts->forced_caid, &ts->ecm_caid, &ts->ecm_pid, &ts->ecm_pids[0], &ts->n_ecm_pids);

	if (ts->forced_ecm_pid)
		ts_get_ecm_info_by_pid(ts->pmt, &ts->ecm_caid, ts->forced_ecm_pid);

	if (ts->ecm_caid) {
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(ts->ecm_caid));
		ts_LOGf("--- | ECM CAID: 0x%04x (%s)\n", ts->ecm_caid, CA_sys);
		if (!ts->forced_ecm_pid) {
			ts_LOGf("--- | ECM pid : 0x%04x (%s)\n", ts->ecm_pid, CA_sys);
		} else {
			ts_LOGf("--- | ECM pid : 0x%04x (%s) (forced: 0x%04x)\n",
				ts->ecm_pid, CA_sys, ts->forced_ecm_pid);
			ts->ecm_pid = ts->forced_ecm_pid;
		}
		if (ts->n_ecm_pids > 1) {
			for (i = 0; i < (int)ts->n_ecm_pids; i++) {
				ts_LOGf("--- | ECM pid : 0x%04x (%s) idx:%d\n", ts->ecm_pids[i], CA_sys, i);
			}
		}
	} else {
		ts_LOGf("*** | ERROR: Can't detect ECM pid.\n");
	}

	if (ts->req_CA_sys == CA_IRDETO) {
		memset(ts->irdeto_chid, 0, sizeof(ts->irdeto_chid));
		ts->irdeto_max_chids = 0;
	}
}

static int sdt_parse_service_name_desc(
	int desc_len, uint8_t *desc,
	uint8_t *service_type,
	uint8_t *pname_len, uint8_t **pname,
	uint8_t *sname_len, uint8_t **sname)
{
	int ofs = 0;
	*pname_len = 0;
	*sname_len = 0;
	*pname = NULL;
	*sname = NULL;
	while (ofs + 2 < desc_len) {
		uint8_t tag = desc[ofs++];
		uint8_t len = desc[ofs++];
		if (tag != 0x48) {
			ofs += len;
			continue;
		}
		// Parse descriptor 0x48 - service_descriptor
		// +3 == +1 for service type, +1 for provider len, +1 for service len
		if (ofs + 3 > desc_len)
			break;

		*service_type = desc[ofs++];
		*pname_len = desc[ofs++];
		if (*pname_len)
			*pname = desc + ofs;
		ofs += *pname_len;
		if (ofs > desc_len)
			break;

		*sname_len = desc[ofs++];
		if (*sname_len)
			*sname = desc + ofs;

		return 1;
	}
	return 0;
}

void process_sdt(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int i;

	if (pid != 0x11)
		return;

	handle_table_changes(sdt);

	for(i=0;i<ts->sdt->streams_num;i++) {
		struct ts_sdt_stream *stream = ts->sdt->streams[i];
		uint8_t service_type;
		uint8_t *pname, *sname;
		uint8_t pname_len, sname_len;
		if (sdt_parse_service_name_desc(
			stream->descriptor_size, stream->descriptor_data,
			&service_type,
			&pname_len, &pname, &sname_len, &sname))
		{
			int r;
			for (r = 0; r < pname_len; r++) {
				if (pname[r] < ' ')
					pname[r] = '*';
			}
			for (r = 0; r < sname_len; r++) {
				if (sname[r] < ' ')
					sname[r] = '*';
			}
			ts_LOGf("SDT | Service 0x%04x (%5d) Type: 0x%02x (%s) Provider: \"%.*s\" Service: \"%.*s\"\n",
				stream->service_id, stream->service_id,
				service_type,
				// The service types are described in Table 87 of
				// ETSI EN 300 468 v1.12.1 and also in annex I of the
				// same document.
				service_type == 0x01 ? "Tv" :
				service_type == 0x02 ? "Radio" :
				service_type == 0x11 ? "Tv/HD" :
				service_type == 0x16 ? "Tv/h264" :
				service_type == 0x19 ? "Tv/HD/h264" :
				service_type == 0x1c ? "Tv/3d" : "unknown",
				pname_len, (char *)pname,
				sname_len, (char *)sname);
		} else {
			ts_LOGf("SDT | Service 0x%04x (%5d)\n",
				stream->service_id, stream->service_id);
		}
	}
}

#define dump_sz      (15)
#define dump_buf_sz  (dump_sz * 6)

static void __process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];

	show_ts_pack(ts, pid, "emm", NULL, ts_packet);

	ts->emm_input_count++;

	ts->emm = ts_privsec_push_packet(ts->emm, ts_packet);
	if (!ts->emm->initialized)
		return;

	struct ts_header *th = &ts->emm->ts_header;
	struct ts_section_header *sec = ts->emm->section_header;

	int emm_ok = 1;
	if (ts->emm_filters_num)
		emm_ok = filter_match_emm(ts, sec->section_data, sec->section_data_len);

	if (ts->debug_level >= 2) {
		ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
		ts_LOGf("EMM | SID 0x%04x CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %4d %s %s..\n",
			ts->service_id,
			ts->emm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			emm_ok == 1 ? "Data:" : "SKIP:",
			dump);
	}

	if (emm_ok && sec->section_data_len < CAMD35_DATA_SIZE)
		camd_process_packet(ts, camd_msg_alloc(EMM_MSG, ts->emm_caid, ts->service_id, sec->section_data, sec->section_data_len));
	else
		ts->emm_skipped_count++;

	ts_privsec_copy(ts->emm, ts->last_emm);
	ts_privsec_clear(ts->emm);
}

static void __process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];

	ts->ecm = ts_privsec_push_packet(ts->ecm, ts_packet);
	if (!ts->ecm->initialized)
		return;

	if (ts->req_CA_sys == CA_IRDETO) {
		uint8_t idx     = ts->ecm->section_header->section_data[4];
		uint8_t max_idx = ts->ecm->section_header->section_data[5];
		uint16_t chid   = (ts->ecm->section_header->section_data[6] << 8) | ts->ecm->section_header->section_data[7];

		if (max_idx != ts->irdeto_max_chids) {
			memset(ts->irdeto_chid, 0, sizeof(ts->irdeto_chid));
			ts->irdeto_max_chids = max_idx;
		}

		bool ecm_ok = false;
		const char *filter_type;
		switch (ts->irdeto_ecm_filter_type) {
		case IRDETO_FILTER_IDX : ecm_ok = (idx == ts->irdeto_ecm_idx); filter_type = " BY IDX"; break;
		case IRDETO_FILTER_CHID: ecm_ok = (chid == ts->irdeto_ecm_chid); filter_type = " BY CHID"; break;
		}

		if (ts->irdeto_chid[idx].seen < 1) {
			ts_LOGf("CAS | Seen Irdeto CHID 0x%04x (idx %u/%u)%s%s\n", chid, idx, max_idx,
				ecm_ok ? " *SELECTED*" : "",
				ecm_ok ? filter_type   : "");
			ts->irdeto_chid[idx].seen++;
		}

		if (!ecm_ok) {
			ts_privsec_clear(ts->ecm);
			return;
		}
	}

	struct ts_header *th = &ts->ecm->ts_header;
	struct ts_section_header *sec = ts->ecm->section_header;

	// ECMs should be in these tables.
	if (sec->section_data[0] != 0x80 && sec->section_data[0] != 0x81) {
		ts_privsec_clear(ts->ecm);
		return;
	}

	int duplicate = ts_privsec_is_same(ts->ecm, ts->last_ecm);
	if (duplicate && !ts->is_cw_error)
		ts->ecm_duplicate_count++;
	if (!ts->ecm_change_time.tv_sec && !ts->ecm_change_time.tv_usec) // The first time
		gettimeofday(&ts->ecm_change_time, NULL);
	if (!duplicate || ts->is_cw_error) {
		if (ts->ecm_cw_log) {
			struct timeval tv;
			gettimeofday(&tv, NULL);
			ts_LOGf("ECC | SID 0x%04x ------------ EcmChng: %5llu ms\n",
				ts->service_id,
				timeval_diff_msec(&ts->ecm_change_time, &tv));
			ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
			ts_LOGf("ECM | SID 0x%04x CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %4d Data: %s..\n",
				ts->service_id,
				ts->ecm_caid,
				th->pid,
				sec->table_id,
				sec->section_data_len,
				dump);
		}
		gettimeofday(&ts->ecm_change_time, NULL);
		ts->is_cw_error = 0;
		camd_process_packet(ts, camd_msg_alloc(ECM_MSG, ts->ecm_caid, ts->service_id, sec->section_data, sec->section_data_len));
	} else if (ts->debug_level >= 3) {
		ts_LOGf("ECM | SID 0x%04x CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %4d Data: -dup-\n",
			ts->service_id,
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len);
	}
	ts_privsec_copy(ts->ecm, ts->last_ecm);
	ts_privsec_clear(ts->ecm);

	show_ts_pack(ts, pid, !duplicate ? "ecm" : "ec+", NULL, ts_packet);
}

// There are cryptosystems that are puting more than one PSI table
// in TS packet. IRDETO is such example. Because libtsfuncs assumes
// that one ts packet can produce maximum 1 PSI table, the following
// workaround is used for EMM/ECM private sections. Basically we detect
// if after the section there is something else than 0xff (filler) and
// if there is something change ts_packet pointer field to point to
// start of the potential section and reparse section.
void process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int section_end;

	if (!ts->process_ecm)
		return;

	if (!ts->ecm_pid || ts->ecm_pid != pid)
		return;

process_psi:
	ts->tmp_ecm = ts_privsec_push_packet(ts->tmp_ecm, ts_packet);
	if (!ts->tmp_ecm->initialized) {
		__process_ecm(ts, pid, ts_packet);
		return;
	}

	section_end = ts->tmp_ecm->section_header->pointer_field + ts->tmp_ecm->section_header->section_length + 3 + 4 + 1;
	if (section_end < 188 && ts_packet[section_end] != 0xff) {
		__process_ecm(ts, pid, ts_packet);
		ts_packet[4] = ts_packet[4] + ts->tmp_ecm->section_header->section_length + 3;
		ts_privsec_clear(ts->tmp_ecm);
		goto process_psi;
	} else {
		__process_ecm(ts, pid, ts_packet);
	}

	ts_privsec_clear(ts->tmp_ecm);
}

void process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int section_end;

	if (!ts->process_emm)
		return;

process_psi:
	ts->tmp_emm = ts_privsec_push_packet(ts->tmp_emm, ts_packet);
	if (!ts->tmp_emm->initialized) {
		__process_emm(ts, pid, ts_packet);
		return;
	}

	section_end = ts->tmp_emm->section_header->pointer_field + ts->tmp_emm->section_header->section_length + 3 + 4 + 1;
	if (section_end < 188 && ts_packet[section_end] != 0xff) {
		__process_emm(ts, pid, ts_packet);
		ts_packet[4] = ts_packet[4] + ts->tmp_emm->section_header->section_length + 3;
		ts_privsec_clear(ts->tmp_emm);
		goto process_psi;
	} else {
		__process_emm(ts, pid, ts_packet);
	}

	ts_privsec_clear(ts->tmp_emm);
}
