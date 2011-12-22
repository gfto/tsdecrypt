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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"
#include "notify.h"

int camd_tcp_connect(struct in_addr ip, int port) {
	ts_LOGf("CAM | Connecting to server %s:%d\n", inet_ntoa(ip), port);

	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)	{
		ts_LOGf("CAM | Could not create socket | %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_in sock;
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr = ip;
	if (do_connect(fd, (struct sockaddr *)&sock, sizeof(sock), 1000) < 0) {
		ts_LOGf("CAM | Could not connect to server %s:%d | %s\n", inet_ntoa(ip), port, strerror(errno));
		close(fd);
		sleep(1);
		return -1;
	}

	int flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

	ts_LOGf("CAM | Connected to fd:%d\n", fd);
	return fd;
}

static int camd_recv_cw(struct ts *ts) {
	struct camd *c = &ts->camd;
	struct timeval tv1, tv2, last_ts_keyset;
	static uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint16_t ca_id = 0;
	uint16_t idx = 0;
	int ret;

	gettimeofday(&tv1, NULL);
	ret = c->ops.get_cw(c, &ca_id, &idx, c->key->cw);
	gettimeofday(&tv2, NULL);

	if (ret <= 0) {
		if (ret == -1) { // Fatal error it is better to reconnect to server.
			ts_LOGf("ERR | No code word has been received (ret = %d)\n", ret);
			c->ops.reconnect(c);
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
	if (c->key->is_valid_cw) {
		c->ecm_recv_errors = 0;

		gettimeofday(&c->key->ts_keyset, NULL);
		c->key->ts = c->key->ts_keyset.tv_sec;
		ts->cw_last_warn = c->key->ts;

		if (memcmp(c->key->cw, invalid_cw, 8) != 0) {
			dvbcsa_key_set   (c->key->cw, c->key->csakey[0]);
			dvbcsa_bs_key_set(c->key->cw, c->key->bs_csakey[0]);
		}
		if (memcmp(c->key->cw + 8, invalid_cw, 8) != 0) {
			dvbcsa_key_set(c->key->cw + 8, c->key->csakey[1]);
			dvbcsa_bs_key_set(c->key->cw + 8, c->key->bs_csakey[1]);
		}
	}

	if (ts->ecm_cw_log) {
		ts_LOGf("CW  | CAID: 0x%04x [ %5llu ms ] ( %6llu ms ) ------ IDX: 0x%04x Data: %s\n",
			ca_id, timeval_diff_msec(&tv1, &tv2),
			timeval_diff_msec(&last_ts_keyset, &tv2),
			idx, cw_dump );
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
		c->ops.reconnect(c);
		return ret;
	}

	ret = camd_recv_cw(ts);
	if (ret < 1) {
		ts->is_cw_error = 1;
		if (ts->key.ts && time(NULL) - ts->key.ts > KEY_VALID_TIME) {
			if (c->key->is_valid_cw)
				notify(ts, "NO_CODE_WORD", "No code word was set in %ld sec. Decryption is disabled.",
					time(NULL) - ts->key.ts);
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
		if (c->emm_recv_errors >= EMM_RECV_ERRORS_LIMIT) {
			ts_LOGf("ERR | Error sending emm packet, reconnecting to camd.\n");
			c->ops.reconnect(c);
			c->emm_recv_errors = 0;
		}
	} else {
			c->emm_recv_errors = 0;
	}
	return ret;
}

static void camd_do_msg(struct camd_msg *msg) {
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

	while (1) {
		struct camd_msg *msg;
		void *req = queue_get(ts->camd.req_queue); // Waits...
		if (!req || ts->camd_stop)
			break;
		msg = queue_get_nowait(ts->camd.ecm_queue);
		if (!msg)
			msg = queue_get_nowait(ts->camd.emm_queue);
		if (!msg)
			break;
		camd_do_msg(msg);
	}
	pthread_exit(EXIT_SUCCESS);
}

void camd_process_packet(struct ts *ts, struct camd_msg *msg) {
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
	c->ops.connect(c);
	// The input is not file, process messages using async thread
	if (!(ts->input.type == FILE_IO && ts->input.fd != 0)) {
		c->req_queue = queue_new();
		c->ecm_queue = queue_new();
		c->emm_queue = queue_new();
		pthread_create(&c->thread, NULL , &camd_thread, ts);
	}
}

void camd_stop(struct ts *ts) {
	struct camd *c = &ts->camd;
	ts->camd_stop = 1;
	if (c->thread) {
		queue_wakeup(c->req_queue);
		pthread_join(c->thread, NULL);
		queue_free(&c->req_queue);
		queue_free(&c->ecm_queue);
		queue_free(&c->emm_queue);
		c->thread = 0;
	}
	c->ops.disconnect(c);
}
