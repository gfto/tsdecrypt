#include "data.h"
#include "tables.h"
#include "camd.h"

#include "libts/tsfuncs.h"
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
	if (pid != 0x00)
		return;

	handle_table_changes(pat);

	for (i=0;i<ts->pat->programs_num;i++) {
		struct ts_pat_program *prg = ts->pat->programs[i];
		if (prg->pid) {
			if (prg->program != 0) {
				ts->pmt_pid    = prg->pid;
				ts->service_id = prg->program;
			}
		}
	}
}

void process_cat(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (pid != 0x01)
		return;

	handle_table_changes(cat);

	ts_get_emm_info(ts->cat, ts->req_CA_sys, &ts->emm_caid, &ts->emm_pid);
	if (ts->emm_caid) {
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(ts->emm_caid));
		ts_LOGf("--- | EMM CAID: 0x%04x (%s)\n", ts->emm_caid, CA_sys);
		ts_LOGf("--- | EMM pid : 0x%04x (%s)\n", ts->emm_pid, CA_sys);
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

	ts_get_ecm_info(ts->pmt, ts->req_CA_sys, &ts->ecm_caid, &ts->ecm_pid);
	if (ts->ecm_caid) {
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(ts->ecm_caid));
		ts_LOGf("--- | ECM CAID: 0x%04x (%s)\n", ts->ecm_caid, CA_sys);
		ts_LOGf("--- | ECM pid : 0x%04x (%s)\n", ts->ecm_pid, CA_sys);
	} else {
		ts_LOGf("*** | ERROR: Can't detect ECM pid.\n");
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
	int duplicate = ts_privsec_is_same(ts->ecm, ts->last_ecm);
	if (!duplicate || ts->is_cw_error) {
		ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d IDX: 0x%04x Data: %s..\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			ts->ecm_counter,
			dump);
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
