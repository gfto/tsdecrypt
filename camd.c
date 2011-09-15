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
#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/md5.h>

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"
#include "libts/tsfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"

static int connect_to(struct in_addr ip, int port) {
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

	ts_LOGf("CAM | Connected to fd:%d\n", fd);
	return fd;
}

static void camd35_init_auth(struct ts *ts) {
	struct camd35 *c = &ts->camd35;
	unsigned char dump[16];

	if (c->auth_token)
		return;

	c->auth_token = crc32(0L, MD5((unsigned char *)c->user, strlen(c->user), dump), 16);

	MD5((unsigned char *)c->pass, strlen(c->pass), dump);

	AES_set_encrypt_key(dump, 128, &c->aes_encrypt_key);
	AES_set_decrypt_key(dump, 128, &c->aes_decrypt_key);
}

static int camd35_connect(struct ts *ts) {
	struct camd35 *c = &ts->camd35;
	if (c->server_fd < 0)
		c->server_fd = connect_to(c->server_addr, c->server_port);
	return c->server_fd;
}

static void camd35_disconnect(struct ts *ts) {
	struct camd35 *c = &ts->camd35;
	shutdown_fd(&c->server_fd);
}

static int camd35_reconnect(struct ts *ts) {
	camd35_disconnect(ts);
	return camd35_connect(ts);
}

static int camd35_recv(struct camd35 *c, uint8_t *data, int *data_len) {
	int i;

	// Read AUTH token
	ssize_t r = fdread(c->server_fd, (char *)data, 4);
	if (r < 4)
		return -1;
	uint32_t auth_token = (((data[0] << 24) | (data[1] << 16) | (data[2]<<8) | data[3]) & 0xffffffffL);
	if (auth_token != c->auth_token)
		ts_LOGf("WARN: recv auth 0x%08x != camd35_auth 0x%08x\n", auth_token, c->auth_token);

	*data_len = 256;
	for (i = 0; i < *data_len; i += 16) { // Read and decrypt payload
		fdread(c->server_fd, (char *)data + i, 16);
		AES_decrypt(data + i, data + i, &c->aes_decrypt_key);
		if (i == 0)
			*data_len = boundary(4, data[1] + 20); // Initialize real data length
	}
	return *data_len;
}

static int camd35_recv_cw(struct ts *ts) {
	struct camd35 *c = &ts->camd35;
	struct timeval tv1, tv2, last_ts_keyset;
	static uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t *data = c->buf;
	int data_len = 0;
	int ret = 0;

	gettimeofday(&tv1, NULL);
READ:
	ret = camd35_recv(c, data, &data_len);
	if (ret < 0) {
		ts_LOGf("CW   | No CW has been received (ret = %d)\n", ret);
		camd35_reconnect(ts);
		return ret;
	}

	// EMM request, ignore it. Sometimes OSCAM sends two EMM requests after CW
	if (data[0] == 0x05)
		goto READ;

	if (data[0] != 0x01) {
		ts_LOGf("CW  | Unxpected server response, skipping it (data[0] == 0x%02x /%s/)\n",
			data[0],
			data[0] == 0x08 ? "No card" : "Unknown");
		c->key->is_valid_cw = 0;
		memcpy(c->key->cw, invalid_cw, 16);
		return 0;
	}

	if (data_len < 48) {
		ts_LOGf("CW  | data_len (%d) mismatch != 48\n", data_len);
		return 0;
	}

	if (data[1] < 0x10) {
		ts_LOGf("CW  | CW len (%d) mismatch != 16\n", data[1]);
		return 0;
	}
	gettimeofday(&tv2, NULL);

	uint16_t ca_id = (data[10] << 8) | data[11];
	uint16_t idx   = (data[16] << 8) | data[17];
	uint8_t *cw = data + 20;
	memcpy(c->key->cw, cw, 16);

	char cw_dump[16 * 6];
	ts_hex_dump_buf(cw_dump, 16 * 6, cw, 16, 0);

	c->key->is_valid_cw = memcmp(c->key->cw, invalid_cw, 16) != 0;

	// At first ts_keyset is not initialized
	last_ts_keyset = c->key->ts_keyset;
	if (c->key->is_valid_cw) {
		gettimeofday(&c->key->ts_keyset, NULL);
		c->key->ts = c->key->ts_keyset.tv_sec;

		dvbcsa_key_set(c->key->cw    , c->key->csakey[0]);
		dvbcsa_key_set(c->key->cw + 8, c->key->csakey[1]);

		dvbcsa_bs_key_set(c->key->cw    , c->key->bs_csakey[0]);
		dvbcsa_bs_key_set(c->key->cw + 8, c->key->bs_csakey[1]);
	}

	ts_LOGf("CW  | CAID: 0x%04x [ %5llu ms ] ( %6llu ms ) ------- IDX: 0x%04x Data: %s\n",
		ca_id, timeval_diff_msec(&tv1, &tv2),
		timeval_diff_msec(&last_ts_keyset, &tv2),
		idx, cw_dump );

	return ret;
}

#undef ERR


static int camd35_send_buf(struct ts *ts, int data_len) {
	struct camd35 *c = &ts->camd35;
	int i;
	uint8_t *bdata = c->buf + 4; // Leave space for auth token

	camd35_connect(ts);
	camd35_init_auth(ts);

	memmove(bdata, c->buf, data_len); // Move data
	init_4b(c->auth_token, c->buf); // Put authentication token

	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(bdata + i, bdata + i, &c->aes_encrypt_key);

	return fdwrite(c->server_fd, (char *)c->buf, data_len + 4);
}

static void camd35_buf_init(struct camd35 *c, uint8_t *data, int data_len) {
	memset(c->buf, 0, CAMD35_HDR_LEN); // Reset header
	memset(c->buf + CAMD35_HDR_LEN, 0xff, CAMD35_BUF_LEN - CAMD35_HDR_LEN); // Reset data
	c->buf[1] = data_len; // Data length
	init_4b(crc32(0L, data, data_len), c->buf + 4); // Data CRC is at buf[4]
	memcpy(c->buf + CAMD35_HDR_LEN, data, data_len); // Copy data to buf
}

static int camd35_send_ecm(struct ts *ts, uint16_t ca_id, uint16_t service_id, uint16_t idx, uint8_t *data, uint8_t data_len) {
	struct camd35 *c = &ts->camd35;
	uint32_t provider_id = 0;
	int to_send = boundary(4, CAMD35_HDR_LEN + data_len);

	camd35_buf_init(c, data, (int)data_len);

	c->buf[0] = 0x00; // CMD ECM request
	init_2b(service_id , c->buf + 8);
	init_2b(ca_id      , c->buf + 10);
	init_4b(provider_id, c->buf + 12);
	init_2b(idx        , c->buf + 16);
	c->buf[18] = 0xff;
	c->buf[19] = 0xff;

	// OSCAM do not like it if ECM's are comming too fast
	// It thinks they are part of a single packet and ignores
	// the data at the end. The usleep() is a hack but works
	if (ts->packet_delay)
		usleep(ts->packet_delay);

	int ret = camd35_send_buf(ts, to_send);
	if (ret <= 0) {
		ts_LOGf("ECM | Error sending packet.\n");
		ts->is_cw_error = 1;
		camd35_reconnect(ts);
		return ret;
	}

	ret = camd35_recv_cw(ts);
	if (ret < 48) {
		ts->is_cw_error = 1;
		if (ts->key.ts && time(NULL) - ts->key.ts > KEY_VALID_TIME)
			c->key->is_valid_cw = 0;
		return 0;
	}

	return ret;
}

static int camd35_send_emm(struct ts *ts, uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	struct camd35 *c = &ts->camd35;
	uint32_t prov_id = 0;
	int to_send = boundary(4, CAMD35_HDR_LEN + data_len);

	camd35_buf_init(c, data, (int)data_len);

	c->buf[0] = 0x06; // CMD incomming EMM
	init_2b(ca_id  , c->buf + 10);
	init_4b(prov_id, c->buf + 12);

	// OSCAM do not like it if EMM's are comming too fast
	// It thinks they are part of a single packet and ignores
	// the data at the end. The usleep() is a hack but works
	if (ts->packet_delay)
		usleep(ts->packet_delay);

	int ret = camd35_send_buf(ts, to_send);
	if (ret <= 0) {
		ts_LOGf("EMM | Error sending packet.\n");
		camd35_reconnect(ts);
	} else {
		c->emm_count++;
	}
	return ret;
}

static void camd_do_msg(struct camd_msg *msg) {
	struct camd35 *c = &msg->ts->camd35;
	if (msg->type == EMM_MSG)
		camd35_send_emm(msg->ts, msg->ca_id, msg->data, msg->data_len);
	if (msg->type == ECM_MSG)
		camd35_send_ecm(msg->ts, msg->ca_id, msg->service_id, msg->idx, msg->data, msg->data_len);

	if (msg->ts->emm_send && c->emm_count_report_interval && c->emm_count_last_report + c->emm_count_report_interval <= time(NULL))
	{
		ts_LOGf("EMM | Send %d messages in %d seconds.\n", c->emm_count, c->emm_count_report_interval);
		c->emm_count = 0;
		c->emm_count_last_report = time(NULL);
	}

	camd_msg_free(&msg);
}

struct camd_msg *camd_msg_alloc_emm(uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	struct camd_msg *c = calloc(1, sizeof(struct camd_msg));
	c->type       = EMM_MSG;
	c->ca_id      = ca_id;
	c->data_len   = data_len;
	memcpy(c->data, data, data_len);
	return c;
}

struct camd_msg *camd_msg_alloc_ecm(uint16_t ca_id, uint16_t service_id, uint16_t idx, uint8_t *data, uint8_t data_len) {
	struct camd_msg *c = calloc(1, sizeof(struct camd_msg));
	c->type       = ECM_MSG;
	c->idx        = idx;
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
	while (1) {
		struct camd_msg *msg = queue_get(ts->camd35.queue); // Waits...
		if (!msg || ts->camd_stop)
			break;
		camd_do_msg(msg);
	}
	pthread_exit(0);
}

void camd_msg_process(struct ts *ts, struct camd_msg *msg) {
	msg->ts = ts;
	if (ts->camd35.thread) {
		queue_add(ts->camd35.queue, msg);
	} else {
		camd_do_msg(msg);
	}
}

void camd_start(struct ts *ts) {
	camd35_connect(ts);
	// The input is not file, process messages using async thread
	if (!(ts->input.type == FILE_IO && ts->input.fd != 0)) {
		ts->camd35.queue = queue_new();
		pthread_create(&ts->camd35.thread, NULL , &camd_thread, ts);
	}
}

void camd_stop(struct ts *ts) {
	ts->camd_stop = 1;
	if (ts->camd35.thread) {
		queue_wakeup(ts->camd35.queue);
		pthread_join(ts->camd35.thread, NULL);
		queue_free(&ts->camd35.queue);
		ts->camd35.thread = 0;
	}
	camd35_disconnect(ts);
}
