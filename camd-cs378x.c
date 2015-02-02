/*
 * cs378x protocol
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

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"

static int cs378x_connect(struct camd *c) {
	if (c->server_fd < 0)
		c->server_fd = connect_client(SOCK_STREAM, c->hostname, c->service);
	return c->server_fd;
}

static void cs378x_disconnect(struct camd *c) {
	shutdown_fd(&c->server_fd);
}

static int cs378x_reconnect(struct camd *c) {
	cs378x_disconnect(c);
	return cs378x_connect(c);
}

static int cs378x_recv(struct camd *c, uint8_t *data, int *data_len) {
	int i;

	// Read AUTH token
	ssize_t r = fdread(c->server_fd, (char *)data, 4);
	if (r < 4)
		return -1;
	uint32_t auth_token = (((data[0] << 24) | (data[1] << 16) | (data[2]<<8) | data[3]) & 0xffffffffL);
	if (auth_token != c->cs378x.auth_token) {
		ts_LOGf("ERR | [%s] recv auth 0x%08x != camd_auth 0x%08x\n",
			c->ops.ident, auth_token, c->cs378x.auth_token);
	}

	*data_len = 256;
	for (i = 0; i < *data_len; i += 16) { // Read and decrypt payload
		fdread(c->server_fd, (char *)data + i, 16);
		AES_decrypt(data + i, data + i, &c->cs378x.aes_decrypt_key);
		if (i == 0)
			*data_len = boundary(4, data[1] + 20); // Initialize real data length
	}
	return *data_len;
}

static int cs378x_send_buf(struct camd *c, int data_len) {
	int i;
	unsigned char dump[16];

	if (cs378x_connect(c) < 0)
		return -1;

	// Prepare auth token (only once)
	if (!c->cs378x.auth_token) {
		c->cs378x.auth_token = crc32(0L, MD5((unsigned char *)c->user, strlen(c->user), dump), 16);

		MD5((unsigned char *)c->pass, strlen(c->pass), dump);

		AES_set_encrypt_key(dump, 128, &c->cs378x.aes_encrypt_key);
		AES_set_decrypt_key(dump, 128, &c->cs378x.aes_decrypt_key);
	}

	uint8_t *bdata = c->cs378x.buf + 4; // Leave space for auth token
	memmove(bdata, c->cs378x.buf, data_len); // Move data
	init_4b(c->cs378x.auth_token, c->cs378x.buf); // Put authentication token

	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(bdata + i, bdata + i, &c->cs378x.aes_encrypt_key);

	return fdwrite(c->server_fd, (char *)c->cs378x.buf, data_len + 4);
}

static void cs378x_buf_init(struct camd *c, uint8_t *data, int data_len) {
	memset(c->cs378x.buf, 0, CAMD35_HDR_LEN); // Reset header
	memset(c->cs378x.buf + CAMD35_HDR_LEN, 0xff, CAMD35_BUF_LEN - CAMD35_HDR_LEN); // Reset data
	c->cs378x.buf[1] = data_len; // Data length
	init_4b(crc32(0L, data, data_len), c->cs378x.buf + 4); // Data CRC is at buf[4]
	memcpy(c->cs378x.buf + CAMD35_HDR_LEN, data, data_len); // Copy data to buf
}

static int cs378x_do_ecm(struct camd *c, struct camd_msg *msg) {
	int to_send = boundary(4, CAMD35_HDR_LEN + msg->data_len);

	cs378x_buf_init(c, msg->data, (int)msg->data_len);

	c->cs378x.msg_id++;

	c->cs378x.buf[0] = 0x00; // CMD ECM request
	init_2b(msg->service_id , c->cs378x.buf + 8);
	init_2b(msg->ca_id      , c->cs378x.buf + 10);
	init_4b(0               , c->cs378x.buf + 12); // Provider ID
	init_2b(c->cs378x.msg_id, c->cs378x.buf + 16);
	init_2b(msg->ts->ecm_pid, c->cs378x.buf + 18);

	return cs378x_send_buf(c, to_send);
}

static int cs378x_do_emm(struct camd *c, struct camd_msg *msg) {
	int to_send = boundary(4, CAMD35_HDR_LEN + msg->data_len);

	cs378x_buf_init(c, msg->data, (int)msg->data_len);

	c->cs378x.buf[0] = 0x06; // CMD incomming EMM
	init_2b(msg->ca_id  , c->cs378x.buf + 10);
	init_4b(0           , c->cs378x.buf + 12); // Provider ID

	return cs378x_send_buf(c, to_send);
}

static int cs378x_get_cw(struct camd *c, uint16_t *ca_id, uint16_t *idx, uint8_t *cw) {
	uint8_t *data = c->cs378x.buf;
	int data_len = 0;
	int ret = 0;

READ:
	ret = cs378x_recv(c, data, &data_len);
	if (ret < 0) // Fatal error
		return -1;

	// EMM request, ignore it. Sometimes OSCAM sends two EMM requests after CW
	if (data[0] == 0x05)
		goto READ;

	if (data[0] != 0x01) {
		ts_LOGf("ERR | [%s] Unexpected server response on code word request (ret data[0] == 0x%02x /%s/)\n",
			c->ops.ident,
			data[0],
			data[0] == 0x08 ? "No card" :
			data[0] == 0x44 ? "No code word found" : "Unknown err");
		return 0;
	}

	if (data_len < 48) {
		ts_LOGf("ERR | [%s] Code word packet len != 48 (%d)\n", c->ops.ident, data_len);
		return 0;
	}

	if (data[1] < 0x10) {
		ts_LOGf("ERR | [%s] Code word len != 16 (%d)\n", c->ops.ident, data[1]);
		return 0;
	}

	*ca_id = (data[10] << 8) | data[11];
	*idx   = (data[16] << 8) | data[17];
	memcpy(cw, data + 20, 16);

	return 1;
}

void camd_proto_cs378x(struct camd_ops *ops) {
	ops->ident      = "cs378x";
	ops->proto		= CAMD_CS378X;
	ops->connect	= cs378x_connect;
	ops->disconnect	= cs378x_disconnect;
	ops->reconnect	= cs378x_reconnect;
	ops->do_emm		= cs378x_do_emm;
	ops->do_ecm		= cs378x_do_ecm;
	ops->get_cw		= cs378x_get_cw;
}
