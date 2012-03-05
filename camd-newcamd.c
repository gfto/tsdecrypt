/*
 * newcamd protocol
 * Most of the code is copied from getstream's newcamd protocol implementation.
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

#define _XOPEN_SOURCE 700 // Needed to pull crypt() from unistd.h

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/des.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"

#define NEWCAMD_PROTO_VER      525
#define NEWCAMD_HDR_LEN        8
#define NEWCAMD_FIRST_CMD_NO   0xe0

typedef enum {
	MSG_CLIENT_2_SERVER_LOGIN = NEWCAMD_FIRST_CMD_NO,
	MSG_CLIENT_2_SERVER_LOGIN_ACK,
	MSG_CLIENT_2_SERVER_LOGIN_NAK,
	MSG_CARD_DATA_REQ,
	MSG_CARD_DATA,
	MSG_SERVER_2_CLIENT_NAME,
	MSG_SERVER_2_CLIENT_NAME_ACK,
	MSG_SERVER_2_CLIENT_NAME_NAK,
	MSG_SERVER_2_CLIENT_LOGIN,
	MSG_SERVER_2_CLIENT_LOGIN_ACK,
	MSG_SERVER_2_CLIENT_LOGIN_NAK,
	MSG_ADMIN,
	MSG_ADMIN_ACK,
	MSG_ADMIN_LOGIN,
	MSG_ADMIN_LOGIN_ACK,
	MSG_ADMIN_LOGIN_NAK,
	MSG_ADMIN_COMMAND,
	MSG_ADMIN_COMMAND_ACK,
	MSG_ADMIN_COMMAND_NAK,
	MSG_KEEPALIVE = NEWCAMD_FIRST_CMD_NO + 0x1d
} net_msg_type_t;

static void set_odd_parity(uint8_t *key) {
	DES_set_odd_parity((DES_cblock *)&key[0]);
	DES_set_odd_parity((DES_cblock *)&key[8]);
}

static void des_schedule_key(triple_des_t *td) {
	DES_key_sched((DES_cblock *)&td->des_key[0],&td->ks1);
	DES_key_sched((DES_cblock *)&td->des_key[8],&td->ks2);
}

static void des_key_spread(triple_des_t *td, uint8_t *normal) {
	td->des_key[0]  =   normal[0] & 0xfe;
	td->des_key[1]  = ((normal[0] << 7) | (normal[1] >> 1)) & 0xfe;
	td->des_key[2]  = ((normal[1] << 6) | (normal[2] >> 2)) & 0xfe;
	td->des_key[3]  = ((normal[2] << 5) | (normal[3] >> 3)) & 0xfe;
	td->des_key[4]  = ((normal[3] << 4) | (normal[4] >> 4)) & 0xfe;
	td->des_key[5]  = ((normal[4] << 3) | (normal[5] >> 5)) & 0xfe;
	td->des_key[6]  = ((normal[5] << 2) | (normal[6] >> 6)) & 0xfe;
	td->des_key[7]  =   normal[6] << 1;
	td->des_key[8]  =   normal[7] & 0xfe;
	td->des_key[9]  = ((normal[7] << 7)  | (normal[8] >> 1)) & 0xfe;
	td->des_key[10] = ((normal[8] << 6)  | (normal[9] >> 2)) & 0xfe;
	td->des_key[11] = ((normal[9] << 5)  | (normal[10] >> 3)) & 0xfe;
	td->des_key[12] = ((normal[10] << 4) | (normal[11] >> 4)) & 0xfe;
	td->des_key[13] = ((normal[11] << 3) | (normal[12] >> 5)) & 0xfe;
	td->des_key[14] = ((normal[12] << 2) | (normal[13] >> 6)) & 0xfe;
	td->des_key[15] =   normal[13] << 1;
	set_odd_parity(td->des_key);
};

static uint8_t xor_sum(const uint8_t *mem, int len) {
	uint8_t cs = 0;
	while (len > 0) {
		cs ^= *mem++;
		len--;
	}
	return cs;
}

static int pad_message(uint8_t *data, int len) {
	DES_cblock padBytes;
	uint8_t noPadBytes = (8 - ((len - 1) % 8)) % 8;
	if (len + noPadBytes + 1 >= NEWCAMD_MSG_SIZE - 8)
		return -1;
	DES_random_key(&padBytes);
	memcpy(data + len, padBytes, noPadBytes);
	len += noPadBytes;
	data[len] = xor_sum(data + 2, len - 2);
	return len + 1;
}

static const uint8_t *triple_des_encrypt(triple_des_t *td, uint8_t *data, int len, uint8_t *crypted) {
	DES_cblock ivec;
	DES_random_key(&ivec);
	memcpy(crypted + len, ivec, sizeof(ivec));
	DES_ede2_cbc_encrypt(data + 2, crypted + 2, len - 2, &td->ks1, &td->ks2, (DES_cblock *)ivec, DES_ENCRYPT);
	return crypted;
}

static void triple_des_decrypt(triple_des_t *td, uint8_t *data, int len) {
	if ((len-2) % 8 || (len-2) < 16)
		return;
	DES_cblock ivec;
	len -= sizeof(ivec);
	memcpy(ivec, data+len, sizeof(ivec));
	DES_ede2_cbc_encrypt(data+2, data+2, len-2, &td->ks1, &td->ks2, (DES_cblock *)ivec, DES_DECRYPT);
}

static void prepare_login_key(struct camd *c, const uint8_t *rkey) {
	unsigned int i;
	uint8_t tmpkey[14];
	for(i = 0; i < sizeof(tmpkey); i++)
		tmpkey[i] = rkey[i] ^ c->newcamd.bin_des_key[i];
	des_key_spread(&c->newcamd.td_key, tmpkey);
}

static int newcamd_connect(struct camd *c);

static uint8_t newcamd_send_msg(struct camd *c, const uint8_t *data, int data_len, uint16_t service_id, uint8_t useMsgId) {
	uint8_t netbuf[NEWCAMD_MSG_SIZE];

	if (newcamd_connect(c) < 0)
		return -1;

	if (data_len < 3 || (data_len + NEWCAMD_HDR_LEN + 4) > NEWCAMD_MSG_SIZE) {
		ts_LOGf("ERR | [%s] Bad message size.\n", c->ops.ident);
		return 0; // false
	}

	memset(&netbuf[2], 0, NEWCAMD_HDR_LEN + 2);
	memcpy(&netbuf[NEWCAMD_HDR_LEN + 4], data, data_len);

	netbuf[NEWCAMD_HDR_LEN + 4 + 1] = (data[1] & 0xF0) | (((data_len - 3) >> 8) & 0x0F);
	netbuf[NEWCAMD_HDR_LEN + 4 + 2] = (data_len - 3) & 0xFF;

	data_len += 4;
	netbuf[4] = service_id >> 8;
	netbuf[5] = service_id & 0xFF;

	data_len += NEWCAMD_HDR_LEN;

	if (useMsgId) {
		c->newcamd.msg_id++;
		netbuf[2] = c->newcamd.msg_id >> 8;
		netbuf[3] = c->newcamd.msg_id & 0xFF;
	}

	if ((data_len = pad_message(netbuf, data_len)) < 0) {
		ts_LOGf("ERR | [%s] Pad_message failed.\n", c->ops.ident);
		return 0;
	}

	if ((data = triple_des_encrypt(&c->newcamd.td_key, netbuf, data_len, netbuf)) == 0) {
		ts_LOGf("ERR | [%s] Encrypt failed.\n", c->ops.ident);
		return 0;
	}

	data_len += sizeof(DES_cblock);
	netbuf[0] = (data_len - 2) >> 8;
	netbuf[1] = (data_len - 2) & 0xFF;

	return fdwrite(c->server_fd, (char *)netbuf, data_len);
}

static int newcamd_recv_msg(struct camd *c, uint8_t *data, uint8_t useMsgId) {
	uint8_t *netbuf = c->newcamd.buf;

	if (fdread(c->server_fd, (char *)netbuf, 2) != 2) {
		ts_LOGf("ERR | [%s] Failed to read message.\n", c->ops.ident);
		return 0;
	}

	int mlen = ((netbuf[0] << 8) | netbuf[1]) & 0xFFFF;
	if (mlen > NEWCAMD_MSG_SIZE - 2) {
		ts_LOGf("ERR | [%s] Buffer overflow [mlen = %d]\n", c->ops.ident, mlen);
		return 0;
	}

	if (fdread(c->server_fd, (char *)netbuf+2, mlen) != mlen) {
		ts_LOGf("ERR | [%s] Failed to read message.\n", c->ops.ident);
		return 0;
	}

	mlen += 2;
	triple_des_decrypt(&c->newcamd.td_key, netbuf, mlen);
	mlen -= sizeof(DES_cblock);
	if (xor_sum(netbuf + 2, mlen - 2)) {
		ts_LOGf("ERR | [%s] Checksum error.\n", c->ops.ident);
		return 0;
	}

	int retlen = (((netbuf[5 + NEWCAMD_HDR_LEN] << 8) | netbuf[6 + NEWCAMD_HDR_LEN]) & 0x0FFF) + 3;

	if (useMsgId) {
		uint16_t tmp = ((netbuf[2] << 8) | netbuf[3]) & 0xFFFF;
		if (c->newcamd.msg_id != tmp) {
			ts_LOGf("ERR | [%s] Bad msg_id %04X != %04X\n", c->ops.ident, c->newcamd.msg_id, tmp);
			return -2;
		}
	}

	memmove(data, netbuf + 4 + NEWCAMD_HDR_LEN, retlen);

	return retlen;
}

static uint8_t newcamd_send_cmd(struct camd *c, net_msg_type_t cmd) {
	uint8_t data[3] = { 0, 0, 0 };
	data[0] = cmd;
	return newcamd_send_msg(c, data, sizeof(data), 0, 0);
}

static int newcamd_recv_cmd(struct camd *c) {
	uint8_t buffer[NEWCAMD_MSG_SIZE];
	if (newcamd_recv_msg(c, buffer, 0) != 3)
		return -1;
	return buffer[0];
}

static void newcamd_init_card_data(struct camd *c, struct newcamd *nc, uint8_t *buffer) {
	int i;
	char msg_buffer[32];

	nc->caid = (buffer[4] << 8) | buffer[5];

	for(i = 0; i < 8; i++)
		sprintf(&msg_buffer[i*2], "%02X", buffer[6 + i]);

	ts_LOGf("CAM | [%s] Card info: CAID 0x%04X Admin=%s srvUA=%s\n",
		c->ops.ident, nc->caid, (buffer[3]==1) ? "YES" : "NO", msg_buffer);
	memcpy(nc->ua, &buffer[6], 8);

	// Parse providers
	uint8_t is_ok = 0;
	nc->num_of_provs = buffer[14];
	for (i = 0; i < nc->num_of_provs; i++) {
		if (nc->prov_ident_manual == 0) {
			memcpy(nc->provs_ident[i], &buffer[15+11*i], 3);
			memcpy(nc->provs_id[i], &buffer[18+11*i], 8);
		} else {
			if (!memcmp(nc->provs_ident[0], &buffer[15+11*i], 3)) {
				is_ok = 1;
				memcpy(nc->provs_id[0], &buffer[18+11*i], 8);
			} else {
				continue;
			}
		}
		uint8_t debug_idx = (nc->prov_ident_manual == 1) ? 0 : i;
		ts_LOGf("CAM | [%s] Card info: Provider %d : %02X%02X%02X : %02X%02X%02X%02X%02X%02X%02X%02X\n",
				c->ops.ident,
				debug_idx,
				nc->provs_ident[debug_idx][0], nc->provs_ident[debug_idx][1],
				nc->provs_ident[debug_idx][2], nc->provs_id[debug_idx][0],
				nc->provs_id[debug_idx][1], nc->provs_id[debug_idx][2],
				nc->provs_id[debug_idx][3], nc->provs_id[debug_idx][4],
				nc->provs_id[debug_idx][5], nc->provs_id[debug_idx][6],
				nc->provs_id[debug_idx][7]);

		if (nc->prov_ident_manual == 1 && is_ok == 1) {
			nc->num_of_provs = 1;
			break;
		}
	}
}

static int newcamd_login(struct camd *c) {
	uint8_t *buffer = c->newcamd.buf;

	c->newcamd.caid = 0;
	c->newcamd.msg_id = 0;

	uint8_t rand_data[14];
	if (fdread(c->server_fd, (char *)rand_data, sizeof(rand_data)) != 14) {
		ts_LOGf("ERR | [%s] Can't read protocol handshake.\n", c->ops.ident);
		return 0;
	}

	char *crPasswd = crypt(c->pass, "$1$abcdefgh$");
	if (!crPasswd) {
		ts_LOGf("ERR | [%s] Can't crypt password.\n", c->ops.ident);
		sleep(1);
		return -1;
	}

	const int userLen = strlen(c->user) + 1;
	const int passLen = strlen(crPasswd) + 1;

	// prepare login message
	buffer[0] = MSG_CLIENT_2_SERVER_LOGIN;
	buffer[1] = 0;
	buffer[2] = userLen + passLen;
	memcpy(&buffer[3], c->user, userLen);
	memcpy(&buffer[3 + userLen], crPasswd, passLen);

	prepare_login_key(c, rand_data);
	des_schedule_key(&c->newcamd.td_key);

	if (!newcamd_send_msg(c, buffer, buffer[2] + 3, 0, 1) ||
		newcamd_recv_cmd(c) != MSG_CLIENT_2_SERVER_LOGIN_ACK)
	{
		ts_LOGf("ERR | [%s] Login failed. Check user/pass/des-key.\n", c->ops.ident);
		free(crPasswd);
		sleep(1);
		return 0;
	}

	// Prepare session key
	uint8_t tmpkey[14];
	memcpy(tmpkey, c->newcamd.bin_des_key, sizeof(tmpkey));
	int i;
	for(i = 0; i < (passLen - 1); ++i)
		tmpkey[i % 14] ^= crPasswd[i];
	des_key_spread(&c->newcamd.td_key, tmpkey);
	des_schedule_key(&c->newcamd.td_key);

	if (!newcamd_send_cmd(c, MSG_CARD_DATA_REQ) || newcamd_recv_msg(c, buffer, 0) <= 0) {
		ts_LOGf("ERR | [%s] MSG_CARD_DATA_REQ error.\n", c->ops.ident);
		return 0;
	}

	if (buffer[0] == MSG_CARD_DATA) {
		newcamd_init_card_data(c, &c->newcamd, buffer);
	} else {
		ts_LOGf("ERR | [%s] MSG_CARD_DATA response error.\n", c->ops.ident);
	}

	return 1;
}

static int newcamd_connect(struct camd *c) {
	if (c->server_fd < 0) {
		c->server_fd = camd_tcp_connect(c->server_addr, c->server_port);
		if (!newcamd_login(c)) {
			shutdown_fd(&c->server_fd);
			return -1;
		}
	}
	return c->server_fd;
}

static void newcamd_disconnect(struct camd *c) {
	shutdown_fd(&c->server_fd);
}

static int newcamd_reconnect(struct camd *c) {
	newcamd_disconnect(c);
	return newcamd_connect(c);
}

static int newcamd_do_ecm(struct camd *c, struct camd_msg *msg) {
	int ret = newcamd_send_msg(c, msg->data, msg->data_len, msg->service_id, 1);
	return ret <= 0 ? -1 : ret;
}

static int newcamd_do_emm(struct camd *c, struct camd_msg *msg) {
	uint8_t *buf = c->newcamd.buf;
	int ret;

	ret = newcamd_send_msg(c, msg->data, msg->data_len, msg->service_id, 1);
	if (ret <= 0)
		return -1;

	int data_len = newcamd_recv_msg(c, buf, 1);
	if (data_len >= 3) {
		if (buf[1] & 0x10)
			return 1; // OK
		ts_LOGf("ERR | [%s] EMM rejected by card.\n", c->ops.ident);
	} else {
		ts_LOGf("ERR | [%s] EMM unexpected server response (data_len=%d, buf[1]=0x%02x).\n",
			c->ops.ident, data_len, buf[1]);
	}

	return 0; // Error
}

static int newcamd_get_cw(struct camd *c, uint16_t *ca_id, uint16_t *idx, uint8_t *cw) {
	int ret;
	int sync_try = 0;
	uint8_t *buf = c->newcamd.buf;

	while((ret = newcamd_recv_msg(c, buf, 1)) == -2) {
		ts_LOGf("ERR | [%s] msg_id sync error. retrying...\n", c->ops.ident);
		if (++sync_try > ECM_QUEUE_HARD_LIMIT) {
			ts_LOGf("ERR | [%s] Can't sync msg_id after %d tries.\n", c->ops.ident, sync_try);
			return -1;
		}
	}

	if (ret != 19) {
		if (ret == 3) {
			ts_LOGf("ERR | [%s] Card was not able to decode the channel.\n", c->ops.ident);
			return 0;
		} else {
			ts_LOGf("ERR | [%s] Unexpected CAMD server response (code %d).\n", c->ops.ident, ret);
			return -1;
		}
	}

	*ca_id = c->newcamd.caid;
	*idx   = 0; // FIXME
	memcpy(cw, c->newcamd.buf + 3, 16);
	return 1;
}

void camd_proto_newcamd(struct camd_ops *ops) {
	strcpy(ops->ident, "newcamd");
	ops->proto		= CAMD_NEWCAMD;
	ops->connect	= newcamd_connect;
	ops->disconnect	= newcamd_disconnect;
	ops->reconnect	= newcamd_reconnect;
	ops->do_emm		= newcamd_do_emm;
	ops->do_ecm		= newcamd_do_ecm;
	ops->get_cw		= newcamd_get_cw;
}
