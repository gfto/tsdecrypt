/*
 * CA system specific fixups
 * Copyright (C) 2010-2012 OSCAM Developers.
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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

#include "libtsfuncs/tsfuncs.h"

#include "fixups.h"

static int DEBUG = 0;

static uint8_t emm_global[1024];
static int emm_global_len = 0;

static void ts_LOGf_hd(uint8_t *buf, int len, const char *fmt, ...) {
	if (!DEBUG)
		return;
	char msg[1024];
	char msg2[1024];
	unsigned int i;
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg)-1, fmt, args);
	va_end(args);
	msg[sizeof(msg)-2] = '\n';
	msg[sizeof(msg)-1] = '\0';
	ts_hex_dump_buf(msg2, sizeof(msg2), buf, len, 16);
	for (i = 0; i < strlen(msg); i++) {
		if (msg[i] == '\n')
			msg[i] = ' ';
	}
	ts_LOGf("XXX: %s, len: %d:\n%s\n", msg, len, msg2);
}

#define dbg_ts_LOGf_hd(...) \
	do { if (DEBUG) ts_LOGf_hd(__VA_ARGS__); } while (0)

#define dbg_ts_LOGf(...) \
	do { if (DEBUG) ts_LOGf(__VA_ARGS__); } while (0)

static void sort_nanos(unsigned char *dest, const unsigned char *src, int src_len) {
	int dst_pos = 0, marker = -1, src_pos, nano, nano_len;
	do {
		nano = 0x100;
		for (src_pos = 0; src_pos < src_len; ) {
			nano_len = src[src_pos + 1] + 2;
			if (src[src_pos] == marker) {
				if (dst_pos + nano_len > src_len) {
					// ERROR
					memset(dest, 0, src_len);
					return;
				}
				memcpy(dest + dst_pos, src + src_pos, nano_len);
				dst_pos += nano_len;
			} else if (src[src_pos] > marker && src[src_pos] < nano) {
				nano = src[src_pos];
			}
			src_pos += nano_len;
		}
		if (nano >= 0x100)
			break;
		marker = nano;
	} while (1);
}


int viaccess_reassemble_emm(uint8_t *buffer, unsigned int *len) {
	if (*len > 500)
		return 0;

	switch (buffer[0]) {
	case 0x8c:
	case 0x8d: { // emm-s part 1
		if (!memcmp(emm_global, buffer, *len))
			return 0;
		// copy first part of the emm-s
		memcpy(emm_global, buffer, *len);
		emm_global_len = *len;
		dbg_ts_LOGf_hd(buffer, *len, "viaccess global emm:\n");
		return 0;
	}
	case 0x8e: { // emm-s part 2
		if (!emm_global_len)
			return 0;

		int i, pos = 0;
		unsigned int k;

		// extract nanos from emm-gh and emm-s
		uint8_t emmbuf[1024];

		dbg_ts_LOGf("[viaccess] %s: start extracting nanos\n", __func__);
		// extract from emm-gh
		for (i = 3; i < emm_global_len; i += emm_global[i+1] + 2) {
			//copy nano (length determined by i+1)
			memcpy(emmbuf + pos, emm_global+i, emm_global[i+1] + 2);
			pos += emm_global[i+1] + 2;
		}

		if (buffer[2] == 0x2c) {
			// Add 9E 20 nano + first 32 bytes of emm content
			memcpy(emmbuf+pos, "\x9E\x20", 2);
			memcpy(emmbuf+pos+2, buffer+7, 32);
			pos += 34;

			//add F0 08 nano + 8 subsequent bytes of emm content
			memcpy(emmbuf+pos, "\xF0\x08", 2);
			memcpy(emmbuf+pos+2, buffer+39, 8);
			pos += 10;
		} else {
			// Extract from variable emm-s
			for (k = 7; k < (*len); k += buffer[k+1]+2) {
				// Copy nano (length determined by k+1)
				memcpy(emmbuf + pos, buffer + k, buffer[k + 1] + 2);
				pos += buffer[k + 1] + 2;
			}
		}

		dbg_ts_LOGf_hd(buffer, *len, "[viaccess] %s: %s emm-s\n", __func__, (buffer[2]==0x2c) ? "fixed" : "variable");

		sort_nanos(buffer + 7, emmbuf, pos);
		pos += 7;

		// Calculate emm length and set it on position 2
		buffer[2] = pos - 3;

		dbg_ts_LOGf_hd(emm_global, emm_global_len, "[viaccess] %s: emm-gh\n", __func__);
		dbg_ts_LOGf_hd(buffer    , pos           , "[viaccess] %s: assembled emm\n", __func__);

		*len = pos;
		break;
	}
	}
	return 1;
}

int cryptoworks_reassemble_emm(uint8_t *buffer, unsigned int *len) {
	if (*len > 500)
		return 0;

	// Cryptoworks
	//   Cryptoworks EMM-S have to be assembled by the client from an EMM-SH with table
	//   id 0x84 and a corresponding EMM-SB (body) with table id 0x86. A pseudo EMM-S
	//   with table id 0x84 has to be build containing all nano commands from both the
	//    original EMM-SH and EMM-SB in ascending order.
	//
	switch (buffer[0]) {
	case 0x84: { // emm-sh
		if (memcmp(emm_global, buffer, *len) == 0)
			return 0;
		memcpy(emm_global, buffer, *len);
		emm_global_len = *len;
		return 0;
	}
	case 0x86: { // emm-sb
		dbg_ts_LOGf_hd(buffer, *len, "[cryptoworks] shared emm (EMM-SB) /ORG/\n");
		if (!emm_global_len) {
			dbg_ts_LOGf("[cryptoworks] no 84 part yet.\n");
			return 0;
		}
		// We keep the first 12 bytes of the 0x84 emm (EMM-SH)
		// now we need to append the payload of the 0x86 emm (EMM-SB)
		// starting after the header (&buffer[5])
		// then the rest of the payload from EMM-SH
		// so we should have :
		// EMM-SH[0:12] + EMM-SB[5:len_EMM-SB] + EMM-SH[12:EMM-SH_len]
		// then sort the nano in ascending order
		// update the emm len (emmBuf[1:2])
		//
		int emm_len = *len - 5 + emm_global_len - 12;
		uint8_t tmp[emm_len];
		uint8_t assembled_EMM[emm_len + 12];
		memcpy(tmp, &buffer[5], *len - 5);
		memcpy(tmp + *len - 5, &emm_global[12], emm_global_len - 12);
		memcpy(assembled_EMM, emm_global, 12);
		sort_nanos(assembled_EMM + 12, tmp, emm_len);

		assembled_EMM[1] = ((emm_len + 9) >> 8) | 0x70;
		assembled_EMM[2] = (emm_len + 9) & 0xFF;

		// Copy back the assembled emm in the working buffer
		memcpy(buffer, assembled_EMM, emm_len + 12);
		*len = emm_len + 12;

		emm_global_len = 0;

		dbg_ts_LOGf_hd(buffer, emm_len + 12, "[cryptoworks] shared emm (assembled)\n");
		if (assembled_EMM[11] != emm_len) { // sanity check
			// error in emm assembly
			dbg_ts_LOGf("[cryptoworks] Error assembling Cryptoworks EMM-S %d != %d\n", assembled_EMM[11], emm_len);
			return 0;
		}
		break;
	}
	}

	return 1;
}
