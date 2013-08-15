/*
 * CAMD communications
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "csa.h"
#include "util.h"
#include "camd.h"
#include "notify.h"

int ai_family = AF_UNSPEC;

extern int keep_running;

static uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int connect_client(int socktype, const char *hostname, const char *service) {
	struct addrinfo hints, *res;
	int n;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = ai_family;
	hints.ai_socktype = socktype;

	ts_LOGf("CAM | Connecting to server %s port %s\n", hostname, service);

	n = getaddrinfo(hostname, service, &hints, &res);

	if (n < 0) {
		ts_LOGf("CAM | ERROR: getaddrinfo(%s): %s\n", hostname, gai_strerror(n));
		return -1;
	}

	int sockfd = -1;
	struct addrinfo *ressave = res;
	char str_addr[INET6_ADDRSTRLEN] = { 0 };
	while (res) {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd > -1) {
			my_inet_ntop(res->ai_family, res->ai_addr, str_addr, sizeof(str_addr));
			if (do_connect(sockfd, res->ai_addr, res->ai_addrlen, 1000) < 0) {
				ts_LOGf("CAM | Error connecting to server %s port %s (addr=%s) | %s\n",
					hostname, service, str_addr, strerror(errno));
				close(sockfd);
				sockfd = -1;
			} else {
				break; // connected
			}
		} else {
			ts_LOGf("CAM | Could not create socket: %s\n", strerror(errno));
			sleep(1);
			return -1;
		}
		res = res->ai_next;
	}
	freeaddrinfo(ressave);

	if (socktype == SOCK_STREAM) {
		int flag = 1;
		setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
	}

	ts_LOGf("CAM | Connected to server %s port %s (addr=%s fd=%d).\n",
		hostname, service, str_addr, sockfd);

	return sockfd;
}

static inline void camd_reconnect(struct camd *c) {
	if (!keep_running)
		return;
	if (c->no_reconnect)
		return;
	c->ops.reconnect(c);
}

void camd_set_cw(struct ts *ts, uint8_t *new_cw, int check_validity) {
	struct camd *c = &ts->camd;

	c->ecm_recv_errors = 0;

	gettimeofday(&c->key->ts_keyset, NULL);
	c->key->ts = c->key->ts_keyset.tv_sec;
	ts->cw_last_warn = c->key->ts;

	if (!check_validity || memcmp(new_cw, invalid_cw, 8) != 0)
		csa_set_even_cw(c->key->csakey, new_cw);

	if (!check_validity || memcmp(new_cw + 8, invalid_cw, 8) != 0)
		csa_set_odd_cw(c->key->csakey, new_cw + 8);
}

static int camd_recv_cw(struct ts *ts) {
	struct camd *c = &ts->camd;
	struct timeval tv1, tv2, last_ts_keyset;
	uint16_t ca_id = 0;
	uint16_t idx = 0;
	int ret;

	gettimeofday(&tv1, NULL);
	ret = c->ops.get_cw(c, &ca_id, &idx, c->key->cw);
	gettimeofday(&tv2, NULL);

	if (!keep_running)
		return 0;

	if (ret <= 0) {
		if (ret == -1) { // Fatal error it is better to reconnect to server.
			ts_LOGf("ERR | No code word has been received (ret = %d)\n", ret);
			camd_reconnect(c);
		}
		c->ecm_recv_errors++;
		if (c->ecm_recv_errors >= ECM_RECV_ERRORS_LIMIT) {
			c->key->is_valid_cw = 0;
			memset(c->key->cw, 0, 16); // Invalid CW
		}
		usleep(10000);
		return 0;
	}

	char cw_dump[16 * 6];
	ts_hex_dump_buf(cw_dump, 16 * 6, c->key->cw, 16, 0);

	int valid_cw = memcmp(c->key->cw, invalid_cw, 16) != 0;
	if (!c->key->is_valid_cw && valid_cw) {
		ts_LOGf("CW  | OK: Valid code word was received.\n");
		notify(ts, "CODE_WORD_OK", "Valid code word was received.");
	}
	c->key->is_valid_cw = valid_cw;

	// At first ts_keyset is not initialized
	last_ts_keyset = c->key->ts_keyset;
	if (c->key->is_valid_cw)
		camd_set_cw(ts, c->key->cw, 1);

	if (ts->ecm_cw_log) {
		ts_LOGf("CW  | SID 0x%04x CAID: 0x%04x CW_recv: %5llu ms LastKey: %5llu ms Data: %s\n",
			ts->service_id,
			ca_id,
			timeval_diff_msec(&tv1, &tv2),
			timeval_diff_msec(&last_ts_keyset, &tv2),
			cw_dump );
	}

	return 1;
}

#undef ERR

static int camd_send_ecm(struct ts *ts, struct camd_msg *msg) {
	struct camd *c = &ts->camd;
	int ret = c->ops.do_ecm(c, msg);
	if (ret <= 0) {
		ts_LOGf("ERR | Error sending ecm packet, reconnecting to camd.\n");
		ts->is_cw_error = 1;
		camd_reconnect(c);
		return ret;
	}

	ret = camd_recv_cw(ts);
	if (ret < 1) {
		time_t now = time(NULL);
		ts->is_cw_error = 1;
		if (ts->key.ts && now - ts->key.ts > KEY_VALID_TIME) {
			if (c->key->is_valid_cw) {
				notify(ts, "NO_CODE_WORD", "No code word was set in %ld sec. Decryption is disabled.",
					now - ts->key.ts);
				ts_LOGf("CW  | *ERR* No valid code word was received in %ld seconds. Decryption is disabled.\n",
					now - ts->key.ts);
				ts->cw_last_warn = time(NULL);
				ts->cw_next_warn = ts->cw_last_warn + ts->cw_warn_sec;
				ts->cw_next_warn -= now - ts->key.ts;
				if (ts->cw_next_warn <= ts->cw_last_warn)
					ts->cw_next_warn = ts->cw_last_warn + ts->cw_warn_sec;
			}
			c->key->is_valid_cw = 0;
		}
		return 0;
	}

	return ret;
}

static int camd_send_emm(struct ts *ts, struct camd_msg *msg) {
	struct camd *c = &ts->camd;
	int ret = c->ops.do_emm(c, msg);
	if (ret < 1) {
		c->emm_recv_errors++;
		if (c->check_emm_errors || c->emm_recv_errors >= EMM_RECV_ERRORS_LIMIT) {
			ts_LOGf("ERR | Error sending emm packet, reconnecting to camd.\n");
			camd_reconnect(c);
			c->emm_recv_errors = 0;
		}
	} else {
			c->emm_recv_errors = 0;
	}
	return ret;
}

static void camd_do_msg(struct camd_msg *msg) {
	if (!keep_running)
		goto OUT;
	if (msg->type == EMM_MSG) {
		msg->ts->emm_seen_count++;
		if (camd_send_emm(msg->ts, msg) > 0)
			msg->ts->emm_processed_count++;
	}
	if (msg->type == ECM_MSG) {
		msg->ts->ecm_seen_count++;
		if (camd_send_ecm(msg->ts, msg) > 0)
			msg->ts->ecm_processed_count++;
	}
OUT:
	camd_msg_free(&msg);
}

struct camd_msg *camd_msg_alloc(enum msg_type msg_type, uint16_t ca_id, uint16_t service_id, uint8_t *data, uint8_t data_len) {
	struct camd_msg *c = calloc(1, sizeof(struct camd_msg));
	c->type       = msg_type;
	c->ca_id      = ca_id;
	c->service_id = service_id;
	c->data_len   = data_len;
	memcpy(c->data, data, data_len);
	return c;
}

void camd_msg_free(struct camd_msg **pmsg) {
	struct camd_msg *m = *pmsg;
	if (m) {
		FREE(*pmsg);
	}
}

static void *camd_thread(void *in_ts) {
	struct ts *ts = in_ts;

	set_thread_name("tsdec-camd");

	while (keep_running) {
		struct camd_msg *msg;
		void *req = queue_get(ts->camd.req_queue); // Waits...
		if (ts->camd_stop)
			break;
		if (!req)
			continue;
		msg = queue_get_nowait(ts->camd.ecm_queue);
		if (!msg)
			msg = queue_get_nowait(ts->camd.emm_queue);
		if (!msg)
			continue;
		camd_do_msg(msg);

		if (ts->camd.ecm_queue->items >= ECM_QUEUE_HARD_LIMIT) {
			ts_LOGf("WRN | Too much items (%d) in ECM queue, dropping the oldest.\n", ts->camd.ecm_queue->items);
			while(ts->camd.ecm_queue->items >= ECM_QUEUE_SOFT_LIMIT) {
				msg = queue_get_nowait(ts->camd.ecm_queue);
				camd_msg_free(&msg);
			}
		}

		if (ts->camd.emm_queue->items >= EMM_QUEUE_HARD_LIMIT) {
			ts_LOGf("WRN | Too much items (%d) in EMM queue, dropping the oldest.%s\n",
				ts->camd.emm_queue->items, ts->camd.ops.proto == CAMD_NEWCAMD ?
				" Consider switching to cs378x protocol!" : "");
			while(ts->camd.emm_queue->items >= EMM_QUEUE_SOFT_LIMIT) {
				msg = queue_get_nowait(ts->camd.emm_queue);
				camd_msg_free(&msg);
			}
		}

		// Flush request queue
		while(ts->camd.req_queue->items > ts->camd.emm_queue->items + ts->camd.ecm_queue->items) {
			queue_get_nowait(ts->camd.req_queue);
		}
	}
	// Flush ECM queue
	while (ts->camd.ecm_queue->items) {
		struct camd_msg *msg = queue_get_nowait(ts->camd.ecm_queue);
		camd_msg_free(&msg);
	}
	// Flush EMM queue
	while (ts->camd.emm_queue->items) {
		struct camd_msg *msg = queue_get_nowait(ts->camd.emm_queue);
		camd_msg_free(&msg);
	}

	pthread_exit(EXIT_SUCCESS);
}

void camd_process_packet(struct ts *ts, struct camd_msg *msg) {
	if (!msg)
		return;
	if (ts->camd.constant_codeword)
		return;
	msg->ts = ts;
	if (ts->camd.thread) {
		if (msg->type == EMM_MSG)
			queue_add(ts->camd.emm_queue, msg);
		if (msg->type == ECM_MSG)
			queue_add(ts->camd.ecm_queue, msg);
		queue_add(ts->camd.req_queue, msg);
	} else {
		camd_do_msg(msg);
	}
}

void camd_start(struct ts *ts) {
	struct camd *c = &ts->camd;
	if (c->constant_codeword)
		return;
	c->ops.connect(c);
	// The input is not file, process messages using async thread
	if (ts->threaded) {
		c->req_queue = queue_new();
		c->ecm_queue = queue_new();
		c->emm_queue = queue_new();
		pthread_create(&c->thread, &ts->thread_attr , &camd_thread, ts);
	}
}

void camd_stop(struct ts *ts) {
	struct camd *c = &ts->camd;
	if (c->constant_codeword)
		return;
	ts->camd_stop = 1;
	if (c->thread) {
		queue_add(c->req_queue, NULL);
		queue_wakeup(c->req_queue);
		pthread_join(c->thread, NULL);
		queue_free(&c->req_queue);
		queue_free(&c->ecm_queue);
		queue_free(&c->emm_queue);
		c->thread = 0;
	}
	c->ops.disconnect(c);
}
