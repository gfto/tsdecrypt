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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#include "data.h"
#include "tables.h"
#include "camd.h"

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
		ts_LOGf("PAT | %d services exists. Consider using --service parameter.\n",
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
}

void process_cat(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (pid != 0x01)
		return;

	handle_table_changes(cat);

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

void process_pmt(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	int i;
	if (!pid || pid != ts->pmt_pid)
		return;

	handle_table_changes(pmt);

	pidmap_clear(&ts->pidmap);
	pidmap_set(&ts->pidmap, 0x0000); // PAT
	pidmap_set(&ts->pidmap, 0x0011); // SDT
	pidmap_set(&ts->pidmap, ts->pmt->ts_header.pid); // PMT PID
	pidmap_set(&ts->pidmap, ts->pmt->PCR_pid); // PCR
	for (i=0;i<ts->pmt->streams_num;i++) {
		struct ts_pmt_stream *stream = ts->pmt->streams[i];
		pidmap_set(&ts->pidmap, stream->pid); // Data
	}

	if (ts->forced_caid) {
		ts->ecm_caid = ts->forced_caid;
		ts_get_ecm_info_by_caid(ts->pmt, ts->ecm_caid, &ts->ecm_pid);
	} else {
		ts_get_ecm_info(ts->pmt, ts->req_CA_sys, &ts->ecm_caid, &ts->ecm_pid);
	}

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
	} else {
		ts_LOGf("*** | ERROR: Can't detect ECM pid.\n");
	}
}

static int sdt_parse_service_name_desc(
	int desc_len, uint8_t *desc,
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
		// Parse descriptor 0x48 - Service name descriptor
		// +3 == +1 for service type, +1 for provider len, +1 for service len
		if (ofs + 3 > desc_len)
			break;

		ofs++; // Skip service type

		*pname_len = desc[ofs++];
		if (*pname_len)
			*pname = desc + ofs;
		ofs += *pname_len;
		if (ofs > desc_len)
			break;

		*sname_len = desc[ofs++];
		if (*sname_len)
			*sname = desc + ofs;
		ofs += *sname_len;

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
		uint8_t *pname, *sname;
		uint8_t pname_len, sname_len;
		if (sdt_parse_service_name_desc(
			stream->descriptor_size, stream->descriptor_data,
			&pname_len, &pname, &sname_len, &sname))
		{
			ts_LOGf("SDT | Service 0x%04x (%5d) Provider: \"%.*s\" Service: \"%.*s\"\n",
				stream->service_id, stream->service_id,
				pname_len, (char *)pname,
				sname_len, (char *)sname);
		} else {
			ts_LOGf("SDT | Service 0x%04x (%5d)\n",
				stream->service_id, stream->service_id);
		}
	}
}

#define dump_sz      (16)
#define dump_buf_sz  (dump_sz * 6)

static void __process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];

	show_ts_pack(ts, pid, "emm", NULL, ts_packet);

	if (!ts->emm_send)
		return;

	ts->emm = ts_privsec_push_packet(ts->emm, ts_packet);
	if (!ts->emm->initialized)
		return;

	struct ts_header *th = &ts->emm->ts_header;
	struct ts_section_header *sec = ts->emm->section_header;
	if (ts->debug_level >= 2) {
		ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
		ts_LOGf("EMM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d ----------- Data: %s..\n",
			ts->emm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			dump);
	}
	camd_msg_process(ts, camd_msg_alloc_emm(ts->emm_caid, sec->section_data, sec->section_data_len));
	ts_privsec_copy(ts->emm, ts->last_emm);
	ts_privsec_clear(ts->emm);
}

static void __process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];

	ts->ecm = ts_privsec_push_packet(ts->ecm, ts_packet);
	if (!ts->ecm->initialized)
		return;

	if (ts->req_CA_sys == CA_IRDETO) {
		int type = ts->ecm->section_header->section_data[4];
		if (type != ts->irdeto_ecm) {
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
	if (!duplicate || ts->is_cw_error) {
		if (ts->ecm_cw_log) {
			ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
			ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d IDX: 0x%04x Data: %s..\n",
				ts->ecm_caid,
				th->pid,
				sec->table_id,
				sec->section_data_len,
				ts->ecm_counter,
				dump);
		}
		if (ts->is_cw_error)
			ts->ecm_counter--;
		ts->is_cw_error = 0;
		camd_msg_process(ts, camd_msg_alloc_ecm(ts->ecm_caid, ts->service_id, ts->ecm_counter++, sec->section_data, sec->section_data_len));
	} else if (ts->debug_level >= 3) {
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d IDX: 0x%04x Data: -dup-\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			ts->ecm_counter - 1);
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

	if (ts->emm_only)
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

	if (!ts->emm_pid || ts->emm_pid != pid)
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
