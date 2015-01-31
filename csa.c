/*
 * CSA functions
 * Copyright (C) 2011-2012 Unix Solutions Ltd.
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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>

#include "libfuncs/libfuncs.h"

#include "csa.h"

csakey_t *csa_key_alloc(void) {
	struct csakey *key = calloc(1, sizeof(struct csakey));
	key->s_csakey[0] = dvbcsa_key_alloc();
	key->s_csakey[1] = dvbcsa_key_alloc();
	key->bs_csakey[0] = dvbcsa_bs_key_alloc();
	key->bs_csakey[1] = dvbcsa_bs_key_alloc();
	key->ff_csakey = ffdecsa_key_alloc();
	return (csakey_t *)key;
}

void csa_key_free(csakey_t **pcsakey) {
	struct csakey *key = *((struct csakey **)pcsakey);
	if (key) {
		dvbcsa_key_free(key->s_csakey[0]);
		dvbcsa_key_free(key->s_csakey[1]);
		dvbcsa_bs_key_free(key->bs_csakey[0]);
		dvbcsa_bs_key_free(key->bs_csakey[1]);
		ffdecsa_key_free(key->ff_csakey);
		FREE(*pcsakey);
	}
}

inline unsigned int csa_get_batch_size(void) {
	if (use_dvbcsa) {
		return dvbcsa_bs_batch_size(); // 32?
	}
	if (use_ffdecsa) {
		return ffdecsa_get_suggested_cluster_size() / 2;
	}
	return 0;
}

inline void csa_set_even_cw(csakey_t *csakey, uint8_t *even_cw) {
	struct csakey *key = (struct csakey *)csakey;
	dvbcsa_key_set(even_cw, key->s_csakey[0]);
	dvbcsa_bs_key_set(even_cw, key->bs_csakey[0]);
	ffdecsa_set_even_cw(key->ff_csakey, even_cw);
}

inline void csa_set_odd_cw(csakey_t *csakey, uint8_t *odd_cw) {
	struct csakey *key = (struct csakey *)csakey;
	dvbcsa_key_set(odd_cw, key->s_csakey[1]);
	dvbcsa_bs_key_set(odd_cw, key->bs_csakey[1]);
	ffdecsa_set_odd_cw(key->ff_csakey, odd_cw);
}

inline void csa_decrypt_single_packet(csakey_t *csakey, uint8_t *ts_packet) {
	struct csakey *key = (struct csakey *)csakey;
	if (use_dvbcsa) {
		unsigned int key_idx = ts_packet_get_scrambled(ts_packet) - 2;
		unsigned int payload_offset = ts_packet_get_payload_offset(ts_packet);
		ts_packet_set_not_scrambled(ts_packet);
		dvbcsa_decrypt(key->s_csakey[key_idx], ts_packet + payload_offset, 188 - payload_offset);
	}
	if (use_ffdecsa) {
		uint8_t *cluster[3] = { ts_packet, ts_packet + 188, NULL };
		ffdecsa_decrypt_packets(key->ff_csakey, cluster);
	}
}

inline void csa_decrypt_multiple_even(csakey_t *csakey, struct csa_batch *batch) {
	struct csakey *key = (struct csakey *)csakey;
	dvbcsa_bs_decrypt(key->bs_csakey[0], (struct dvbcsa_bs_batch_s *)batch, 184);
}

inline void csa_decrypt_multiple_odd(csakey_t *csakey, struct csa_batch *batch) {
	struct csakey *key = (struct csakey *)csakey;
	dvbcsa_bs_decrypt(key->bs_csakey[1], (struct dvbcsa_bs_batch_s *)batch, 184);
}

inline void csa_decrypt_multiple_ff(csakey_t *csakey, uint8_t **cluster) {
	struct csakey *key = (struct csakey *)csakey;
	ffdecsa_decrypt_packets(key->ff_csakey, cluster);
}

/* The following routine is taken from benchbitslice in libdvbcsa */
void dvbcsa_benchmark(void) {
	struct timeval t0, t1;
	struct dvbcsa_bs_key_s *key = dvbcsa_bs_key_alloc();
	unsigned int n, i, npackets = 0;
	unsigned int batch_size = dvbcsa_bs_batch_size();
	uint8_t data[batch_size + 1][188];
	struct dvbcsa_bs_batch_s pcks[batch_size + 1];
	uint8_t cw[8] = { 0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef, };

	dvbcsa_bs_key_set (cw, key);

	printf("Batch size %d packets.\n\n", batch_size);
	if (!batch_size)
		return;

	for (i = 0; i < batch_size; i++) {
		pcks[i].data = data[i];
		pcks[i].len = 184;
		memset(data[i], rand(), pcks[i].len);
	}
	pcks[i].data = NULL;

	gettimeofday(&t0, NULL);
	for (n = (1 << 12) / batch_size; n < (1 << 19) / batch_size; n *= 2) {
		printf(" Decrypting %6u mpegts packets\r", n * batch_size);
		fflush(stdout);
		for (i = 0; i < n; i++) {
			dvbcsa_bs_decrypt(key, pcks, 184);
		}
		npackets += n * batch_size;
	}
	gettimeofday(&t1, NULL);

	unsigned long long usec = timeval_diff_usec(&t0, &t1);
	printf("DONE: %u packets (%u bytes) decrypted in %llu ms = %.1f Mbits/s\n\n",
		npackets,
		npackets * 188,
		usec / 1000,
		(double)(npackets * 188 * 8) / (double)usec
	);

	dvbcsa_bs_key_free(key);
}

void ffdecsa_benchmark(void) {
	struct timeval t0, t1;
	ffdecsa_key_t *key = ffdecsa_key_alloc();
	unsigned int n, i, d, npackets = 0;
	unsigned int batch_size = ffdecsa_get_suggested_cluster_size() / 2;
	uint8_t data[batch_size + 1][188];
	uint8_t *pcks[batch_size * 2 + 1];
	uint8_t ecw[8] = { 0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef, };
	uint8_t ocw[8] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, };

	ffdecsa_set_even_cw(key, ecw);
	ffdecsa_set_odd_cw (key, ocw);

	printf("Batch size %d packets.\n\n", batch_size);
	if (!batch_size)
		return;

	for (i = 0; i < batch_size; i++) {
		memset(data[i], rand(), 188);
		data[i][0] = 0x47;
		data[i][1] = 0x01;
		data[i][2] = 0x02;
		data[i][3] = i & 0x0f;
	}

	gettimeofday(&t0, NULL);
	for (n = (1 << 12) / batch_size; n < (1 << 18) / batch_size; n *= 2) {
		static unsigned int key_idx = 0;
		printf(" Decrypting %6u mpegts packets\r", n * batch_size);
		fflush(stdout);
		for (i = 0; i < n; i++) {
			// ffdecsa_decrypt function modifies data and pcks
			for (d = 0; d < batch_size; d++) {
				pcks[d * 2]     = data[d];
				pcks[d * 2 + 1] = data[d] + 188;
				data[d][3] |= (key_idx == 0) ? (2 << 6) : (3 << 6);
			}
			pcks[d * 2] = NULL;
			key_idx = !!key_idx;
			ffdecsa_decrypt_packets(key, pcks);
		}
		npackets += n * batch_size;
	}
	gettimeofday(&t1, NULL);

	unsigned long long usec = timeval_diff_usec(&t0, &t1);
	printf("DONE: %u packets (%u bytes) decrypted in %llu ms = %.1f Mbits/s\n\n",
		npackets,
		npackets * 188,
		usec / 1000,
		(double)(npackets * 188 * 8) / (double)usec
	);

	dvbcsa_bs_key_free(key);
}

void csa_benchmark(void) {
	srand(time(0));
	printf("Single threaded CSA decoding benchmark : %s\n", DLIB);
	if (use_dvbcsa)
		dvbcsa_benchmark();
	if (use_ffdecsa)
		ffdecsa_benchmark();
}
