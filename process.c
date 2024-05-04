/*
 * Process packets
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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/uio.h>

#include "bitstream.h"
#include "data.h"
#include "csa.h"
#include "tables.h"
#include "util.h"
#include "notify.h"

static unsigned long ts_pack;
static int ts_pack_shown;

char *get_pid_desc(struct ts *ts, uint16_t pid) {
	int i;
	uint16_t nitpid = 0x0010, pmtpid = 0xffff, pcrpid = 0xffff;

	if (ts->pat->initialized) {
		for (i=0;i<ts->pat->programs_num;i++) {
			struct ts_pat_program *prg = ts->pat->programs[i];
			if (prg->pid) {
				if (prg->program == 0)
					nitpid = prg->pid;
			}
		}
	}

	if (ts->pmt->initialized) {
		pmtpid = ts->pmt->ts_header.pid;
		pcrpid = ts->pmt->PCR_pid;
		for (i=0;i<ts->pmt->streams_num;i++) {
			struct ts_pmt_stream *stream = ts->pmt->streams[i];
			if (pid == stream->pid)
				return h222_stream_type_desc(stream->stream_type);
		}
	}

	switch (pid) {
		case 0x0000: return "PAT"; break;
		case 0x0001: return "CAT"; break;
		case 0x0011: return "SDT"; break;
		case 0x0012: return "EPG"; break;
		case 0x0014: return "TDT/TOT"; break;
	}

	if (pid == nitpid)		return "NIT";
	else if (pid == pmtpid)	return "PMT";
	else if (pid == pcrpid)	return "PCR";
	else if (pid == ts->emm_pid)	return "EMM";
	else if (pid == ts->ecm_pid)	return "ECM";

	return "Unknown";
}

void show_ts_pack(struct ts *ts, uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet) {
	char pdump[188 * 6];
	char cw1_dump[8 * 6];
	char cw2_dump[8 * 6];
	if (ts->debug_level >= 4) {
		if (ts_pack_shown)
			return;
		if (ts->debug_level >= 5)
			ts_hex_dump_buf(pdump, 188 * 6, ts_packet, 188, 0);

		int stype = ts_packet_get_scrambled(ts_packet);
		ts_hex_dump_buf(cw1_dump, 8 * 6, ts->key.cw    , 8, 0);
		ts_hex_dump_buf(cw2_dump, 8 * 6, ts->key.cw + 8, 8, 0);
		fprintf(stderr, "@ %s %s %03x %5ld %7ld | %s   %s | %s %s\n",
			stype == 0 ? "------" :
			stype == 2 ? "even 0" :
			stype == 3 ? "odd  1" : "??????",
			wtf,
			pid,
			ts_pack, ts_pack * 188,
			cw1_dump, cw2_dump, extra ? extra : wtf,
			ts->debug_level >= 5 ? pdump : "");
	}
}

static void dump_ts_pack(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (pid == 0x010)		show_ts_pack(ts, pid, "nit", NULL, ts_packet);
	else if (pid == 0x11)	show_ts_pack(ts, pid, "sdt", NULL, ts_packet);
	else if (pid == 0x12)	show_ts_pack(ts, pid, "epg", NULL, ts_packet);
	else					show_ts_pack(ts, pid, "---", NULL, ts_packet);
}

static void decode_packet(struct ts *ts, uint8_t *ts_packet) {
	int scramble_idx = ts_packet_get_scrambled(ts_packet);
	if (scramble_idx > 1) {
		if (ts->key.is_valid_cw) {
			csa_decrypt_single_packet(ts->key.csakey, ts_packet);
		} else {
			// Can't decrypt the packet just make it NULL packet
			if (ts->pid_filter)
				ts_packet_set_pid(ts_packet, 0x1fff);
		}
	}
}

static void decode_buffer(struct ts *ts, uint8_t *data, int data_len) {
	int i;
	int batch_sz = csa_get_batch_size(); // Tested with 32 for libdvbcsa, 70 for FFdecsa (must be multiplied by 2)
	int even_packets = 0;
	int odd_packets  = 0;
	struct csa_batch even_pcks[batch_sz + 1];
	struct csa_batch odd_pcks [batch_sz + 1];
	uint8_t *ff_even_pcks[batch_sz * 2 + 1];
	uint8_t *ff_odd_pcks [batch_sz * 2 + 1];

	int scramble_idx_old = 0;

	time_t now = time(NULL);

	// Prepare batch structure
	for (i = 0; i < batch_sz; i++) {
		uint8_t *ts_packet = data + (i * 188);

		uint16_t pid = ts_packet_get_pid(ts_packet);
		bool in_pidmap = pidmap_get(&ts->pidmap, pid);
		bool is_scrambled = ts_packet_is_scrambled(ts_packet);
		if (in_pidmap && ts->have_valid_pmt) {
			if (is_scrambled) {
				if (ts->last_scrambled_packet_ts < now) {
					ts->stream_is_not_scrambled = 0;
					ts->last_scrambled_packet_ts = now;
				}
			} else {
				if (now - 5 >= ts->last_scrambled_packet_ts) {
					if (ts->last_not_scrambled_packet_ts < now) {
						ts->camd.key->is_valid_cw = 0;
						ts->stream_is_not_scrambled = 1;
						ts->last_not_scrambled_packet_ts = now;
					}
				}
			}
		}
		if (in_pidmap && is_scrambled) {
			if (ts->key.is_valid_cw) {
				int scramble_idx = ts_packet_get_scrambled(ts_packet);
				if (!scramble_idx_old)
					scramble_idx_old = scramble_idx;
				if (use_dvbcsa) {
					uint8_t payload_ofs = ts_packet_get_payload_offset(ts_packet);
					if (scramble_idx == 2) { // scramble_idx 2 == even key
						even_pcks[even_packets].data = ts_packet + payload_ofs;
						even_pcks[even_packets].len  = 188 - payload_ofs;
						even_packets++;
					}
					if (scramble_idx == 3) { // scramble_idx 3 == odd key
						odd_pcks[odd_packets].data = ts_packet + payload_ofs;
						odd_pcks[odd_packets].len  = 188 - payload_ofs;
						odd_packets++;
					}
					ts_packet_set_not_scrambled(ts_packet);
				}
				if (use_ffdecsa) {
					if (scramble_idx == 2) { // scramble_idx 2 == even key
						ff_even_pcks[even_packets * 2    ] = ts_packet;
						ff_even_pcks[even_packets * 2 + 1] = ts_packet + 188;
						even_packets++;
					}
					if (scramble_idx == 3) { // scramble_idx 3 == odd key
						ff_odd_pcks[odd_packets * 2    ] = ts_packet;
						ff_odd_pcks[odd_packets * 2 + 1] = ts_packet + 188;
						odd_packets++;
					}
				}
				if (scramble_idx_old != scramble_idx && !ts->camd.constant_codeword) {
					struct timeval tv;
					gettimeofday(&tv, NULL);
					ts_LOGf("CWC | SID 0x%04x ------------ EcmTime: %5llu ms CW_time: %5llu ms\n",
						ts->service_id,
						timeval_diff_msec(&ts->ecm_change_time, &tv),
						timeval_diff_msec(&ts->key.ts_keyset, &tv));
				}
				scramble_idx_old = scramble_idx;
			} else {
				if (ts->pid_filter)
					ts_packet_set_pid(ts_packet, 0x1fff);
			}
		}
	}

	// Decode packets
	if (even_packets) {
		if (use_dvbcsa) {
			even_pcks[even_packets].data = NULL; // Last one...
			csa_decrypt_multiple_even(ts->key.csakey, even_pcks);
		}
		if (use_ffdecsa) {
			ff_even_pcks[even_packets * 2] = NULL;
			csa_decrypt_multiple_ff(ts->key.csakey, ff_even_pcks);
		}
	}
	if (odd_packets) {
		if (use_dvbcsa) {
			odd_pcks[odd_packets].data = NULL; // Last one...
			csa_decrypt_multiple_odd(ts->key.csakey, odd_pcks);
		}
		if (use_ffdecsa) {
			ff_odd_pcks[odd_packets * 2] = NULL;
			csa_decrypt_multiple_ff(ts->key.csakey, ff_odd_pcks);
		}
	}

	// Fill write buffer
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;

		if (!ts->pid_filter) {
			cbuf_fill(ts->write_buf, ts_packet, 188);
		} else {
			uint16_t pid = ts_packet_get_pid(ts_packet);
			if (pidmap_get(&ts->pidmap, pid)) // PAT or allowed PIDs
				cbuf_fill(ts->write_buf, ts_packet, 188);
		}
	}
}

void *decode_thread(void *_ts) {
	struct ts *ts = _ts;
	uint8_t *data;
	int data_size;
	int req_size = 188 * csa_get_batch_size();

	set_thread_name("tsdec-decode");

	while (!ts->decode_stop) {
		cbuf_peek(ts->decode_buf, req_size, &data_size);
		if (data_size < req_size) {
			usleep(1000);
			continue;
		}
		data = cbuf_get(ts->decode_buf, req_size, &data_size);
		if (data)
			decode_buffer(ts, data, data_size);
	}

	do { // Flush data
		data = cbuf_get(ts->decode_buf, req_size, &data_size);
		if (data)
			decode_buffer(ts, data, data_size);
	} while(data);

	return NULL;
}

/*
	Return value:
		ret        == 0    - No valid payload was found
		ret & 0x01 == 0x01 - PES was found
		ret & 0x02 == 0x02 - PTS was found
		ret & 0x04 == 0x04 - DTS was found
*/
static unsigned int ts_have_valid_pes(uint8_t *buf, unsigned int buffer_size) {
	unsigned int ret = 0;
	uint8_t *buf_end = buf + buffer_size;
	while (buf < buf_end && ts_validate(buf)) {
		uint16_t header_size = TS_HEADER_SIZE + (ts_has_adaptation(buf) ? 1 : 0) + ts_get_adaptation(buf);
		if (ts_get_unitstart(buf) && ts_has_payload(buf) && header_size + PES_HEADER_SIZE_PTS <= TS_SIZE) {
			//printf("Got payload\n");
			if (pes_validate(buf + header_size) && pes_get_streamid(buf + header_size) != PES_STREAM_ID_PRIVATE_2 && pes_validate_header(buf + header_size)) {
				//printf("Got PES\n");
				ret |= 0x01;
				if (pes_has_pts(buf + header_size) && pes_validate_pts(buf + header_size)) {
					ret |= 0x02;
					//printf("Got PTS\n");
					if (header_size + PES_HEADER_SIZE_PTSDTS <= TS_SIZE && pes_has_dts(buf + header_size) && pes_validate_dts(buf + header_size)) {
						//printf("Got DTS\n");
						ret |= 0x04;
					}
				}
			}
		}
		buf += TS_SIZE;
	}
	return ret;
}

static inline void output_write(struct ts *ts, uint8_t *data, unsigned int data_size) {
	if (!data)
		return;
	if (!ts->have_valid_pmt)
		return;
	if (ts->no_output_on_error && !ts->camd.key->is_valid_cw)
		return;
	if (!ts->allow_encrypted_output) {
		int64_t now = get_time();
		int ret;
		if ((ret = ts_have_valid_pes(data, data_size)) == 0) { // Is the output encrypted?
			/* The output is encrypted, check if 1000 ms have passed and if such, notify that we probably have invalid key */
			ts->last_encrypted_output_ts = now;
			if (now > ts->last_decrypted_output_ts + 500000) {
				if (!ts->output_is_encrypted) {
					ts->output_is_encrypted = 1;
					ts_LOGf("OUT | *ERR* The output is encrypted for %" PRId64 " ms, stopping output\n", (now - ts->last_decrypted_output_ts) / 1000);
					notify(ts, "ENCRYPTED_OUTPUT", "The output can not be decrypted");
				}
			}
		} else {
			ts->last_decrypted_output_ts = now;
			if (ts->output_is_encrypted) {
				ts_LOGf("OUT | Got decrypted data: %s %s %s\n",
					(ret & 0x01) == 0x01 ? "PES" : "   ",
					(ret & 0x02) == 0x02 ? "PTS" : "   ",
					(ret & 0x04) == 0x04 ? "DTS" : "   "
				);
				notify(ts, "OUTPUT_OK", "The output is decrypted");
			}
			ts->output_is_encrypted = 0;
		}
		if (ts->output_is_encrypted)
			return;
	}

	if (!ts->rtp_output) {
		if (write(ts->output.fd, data, data_size) < 0) {
			perror("write(output_fd)");
			return;
		}
	} else {
		struct iovec iov[2];
		uint8_t rtp_header[12];
		uint32_t rtime = get_time() * 9 / 100;

		ts->rtp_seqnum++;

		rtp_header[ 0] = 0x80;
		rtp_header[ 1] = 33; // MPEG TS rtp payload type
		rtp_header[ 2] = ts->rtp_seqnum >> 8;
		rtp_header[ 3] = ts->rtp_seqnum & 0xff;
		rtp_header[ 4] = (rtime >> 24) & 0xff;
		rtp_header[ 5] = (rtime >> 16) & 0xff;
		rtp_header[ 6] = (rtime >>  8) & 0xff;
		rtp_header[ 7] =  rtime        & 0xff;

		rtp_header[ 8] = (ts->rtp_ssrc >> 24) & 0xff;
		rtp_header[ 9] = (ts->rtp_ssrc >> 16) & 0xff;
		rtp_header[10] = (ts->rtp_ssrc >>  8) & 0xff;
		rtp_header[11] =  ts->rtp_ssrc        & 0xff;

		iov[0].iov_base = rtp_header;
		iov[0].iov_len  = sizeof(rtp_header);

		iov[1].iov_base = data;
		iov[1].iov_len  = data_size;

		if (writev(ts->output.fd, iov, 2) < 0) {
			perror("writev(output_fd)");
			return;
		}
	}
}

void *write_thread(void *_ts) {
	struct ts *ts = _ts;
	uint8_t *data;
	int data_size;

	set_thread_name("tsdec-write");

	while (!ts->write_stop) {
		data_size = 0;
		cbuf_peek(ts->write_buf, FRAME_SIZE, &data_size);
		if (data_size < FRAME_SIZE) {
			usleep(5000);
			continue;
		}
		data = cbuf_get (ts->write_buf, FRAME_SIZE, &data_size);
		output_write(ts, data, data_size);
	}

	do { // Flush data
		data = cbuf_get(ts->write_buf, FRAME_SIZE, &data_size);
		output_write(ts, data, data_size);
	} while(data);

	return NULL;
}

static void detect_discontinuity(struct ts *ts, uint8_t *ts_packet) {
	uint16_t pid;
	uint8_t cur_cc, last_cc;

	if (!ts->ts_discont)
		return;

	pid = ts_packet_get_pid(ts_packet);
	cur_cc = ts_packet_get_cont(ts_packet);

	if (!pidmap_get(&ts->pid_seen, pid)) {
		if (strcmp(get_pid_desc(ts, pid), "Unknown") == 0)
			return;

		pidmap_set(&ts->pid_seen, pid);
		pidmap_set_val(&ts->cc, pid, cur_cc);
		ts_LOGf("NEW | Input PID 0x%04x appeared (%s)\n",
				pid, get_pid_desc(ts, pid));
		return;
	}

	last_cc = pidmap_get(&ts->cc, pid);
	if (last_cc != cur_cc && ((last_cc + 1) & 0x0f) != cur_cc)
		ts_LOGf("--- | TS discontinuity on PID 0x%04x expected %2d got %2d /%d/ (%s)\n",
				pid,
				((last_cc + 1) & 0x0f), cur_cc,
				(cur_cc - ((last_cc + 1) & 0x0f)) & 0x0f,
				get_pid_desc(ts, pid));
	pidmap_set_val(&ts->cc, pid, cur_cc);
}

void process_packets(struct ts *ts, uint8_t *data, ssize_t data_len) {
	ssize_t i;
	int64_t now = get_time();

	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);

		if (ts->pid_report)
			ts->pid_stats[pid]++;


		ts_pack_shown = 0;

		process_pat(ts, pid, ts_packet);
		process_cat(ts, pid, ts_packet);
		process_pmt(ts, pid, ts_packet);
		process_sdt(ts, pid, ts_packet);
		process_emm(ts, pid, ts_packet);
		process_ecm(ts, pid, ts_packet);

		detect_discontinuity(ts, ts_packet);

		if (!ts_pack_shown)
			dump_ts_pack(ts, pid, ts_packet);

		if (!ts->output_stream)
			continue;

		// Return rewritten PAT
		if (pid == 0x00 && ts->pid_filter && ts->genpat->initialized) {
			if (!ts_packet_is_pusi(ts_packet))
				continue;
			ts_packet_set_cont(ts->genpat->section_header->packet_data, ts->genpat_cc);
			ts->genpat->ts_header.continuity = ts->genpat_cc;
			ts_packet = ts->genpat->section_header->packet_data;
			ts->genpat_cc = (ts->genpat_cc + 1) & 0x0f;
		}

		if (ts->threaded) {
			// Add to decode buffer. The decoder thread will handle it
			if (ts->input_buffer_time == 0) {
				// No input buffer, move packets to decoding buffer
				if (cbuf_fill(ts->decode_buf, ts_packet, 188) != 0) {
					ts_LOGf("Decode buffer is full, waiting...\n");
					cbuf_dump(ts->decode_buf);
					usleep(10000);
				}
			} else {
				// Handle input buffer
				struct packet_buf *p = malloc(sizeof(struct packet_buf));
				p->time = now + (ts->input_buffer_time * 1000); //buffer time is in ms, p->time is in us
				memcpy(p->data, ts_packet, 188);
				list_add(ts->input_buffer, p);
				// Move packets to decrypt buffer
				LNODE *lc, *lctmp;
				list_for_each(ts->input_buffer, lc, lctmp) {
					p = lc->data;
					if (p->time <= now) {
						if (cbuf_fill(ts->decode_buf, p->data, 188) != 0) {
							ts_LOGf("Decode buffer is full, waiting...\n");
							cbuf_dump(ts->decode_buf);
							usleep(10000);
						}
						list_del(ts->input_buffer, &lc);
						free(p);
					} else {
						break;
					}
				}
			}
		} else {
			int allowed_pid = pidmap_get(&ts->pidmap, pid);
			if (allowed_pid) // PAT or allowed PIDs
				decode_packet(ts, ts_packet);
			if (ts->pid_filter) {
				if (allowed_pid) // PAT or allowed PIDs
					output_write(ts, ts_packet, 188);
			} else {
				output_write(ts, ts_packet, 188);
			}
		}

		ts_pack++;
	}
}

void show_pid_report(struct ts *ts) {
	int i;
	if (!ts->pid_report)
		return;

	for (i = 0; i < MAX_PIDS; i++) {
		if (ts->pid_stats[i]) {
			ts_LOGf("PID | %8u packets with PID 0x%04x (%4u) %s\n",
					ts->pid_stats[i], i, i, get_pid_desc(ts, i));
		}
	}
}
