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
	ts_LOGf("Connecting to %s:%d\n", inet_ntoa(ip), port);

	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)	{
		ts_LOGf("Could not create socket | %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_in sock;
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr = ip;
	if (do_connect(fd, (struct sockaddr *)&sock, sizeof(sock), 1000) < 0) {
		ts_LOGf("Could not connect to %s:%d | %s\n", inet_ntoa(ip), port, strerror(errno));
		return -1;
	}

	ts_LOGf("Connected with fd:%d\n", fd);
	return fd;
}

// 4 auth header, 20 header size, 256 max data size, 16 potential padding
#define HDR_LEN     (20)
#define BUF_SIZE	(4 + HDR_LEN + 256 + 16)

static void camd35_init_auth(struct camd35 *c) {
	unsigned char dump[16];

	if (c->auth_token)
		return;

	c->auth_token = crc32(0L, MD5((unsigned char *)c->user, strlen(c->user), dump), 16);

	MD5((unsigned char *)c->pass, strlen(c->pass), dump);

	AES_set_encrypt_key(dump, 128, &c->aes_encrypt_key);
	AES_set_decrypt_key(dump, 128, &c->aes_decrypt_key);
}

int camd35_connect(struct camd35 *c) {
	if (c->server_fd < 0)
		c->server_fd = connect_to(c->server_addr, c->server_port);
	return c->server_fd;
}

void camd35_disconnect(struct camd35 *c) {
	shutdown_fd(&c->server_fd);
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

#define ERR(x) do { ts_LOGf("%s\n", x); return NULL; } while (0)


static uint8_t *camd35_recv_cw(struct camd35 *c) {
	static uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t data[BUF_SIZE];
	int data_len = 0;

NEXT:
	if (camd35_recv(c, data, &data_len) < 0)
		ERR("No data!");

	if (data[0] < 0x01) {
		ts_LOGf("Not valid CW response, skipping it. data[0] = 0x%02x\n", data[0]);
		goto NEXT;
	}

	if (data_len < 48)
		ERR("len mismatch != 48");

	if (data[1] < 0x10)
		ERR("CW len mismatch != 0x10");

	uint16_t ca_id = (data[10] << 8) | data[11];
	uint16_t idx   = (data[16] << 8) | data[17];
	uint8_t *cw = data + 20;
	memcpy(c->key->cw, cw, 16);

	char cw_dump[16 * 6];
	ts_hex_dump_buf(cw_dump, 16 * 6, cw, 16, 0);
	ts_LOGf("CW  | CAID: 0x%04x ---------------------------------- IDX: 0x%04x Data: %s\n", ca_id, idx, cw_dump);

	c->key->is_valid_cw = memcmp(c->key->cw, invalid_cw, 16) != 0;
	dvbcsa_key_set(c->key->cw    , c->key->csakey[0]);
	dvbcsa_key_set(c->key->cw + 8, c->key->csakey[1]);

	return NULL;
}

#undef ERR


static int camd35_send(struct camd35 *c, uint8_t *data, uint8_t data_len) {
	unsigned int i;
	uint8_t buf[BUF_SIZE];
	uint8_t *bdata = buf + 4;

	camd35_connect(c);
	camd35_init_auth(c);

	init_4b(c->auth_token, buf); // Put authentication token
	memcpy(bdata, data, data_len); // Put data

	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(data + i, bdata + i, &c->aes_encrypt_key);

	return fdwrite(c->server_fd, (char *)buf, data_len + 4);
}

static void camd35_buf_init(struct camd35 *c, uint8_t *buf, uint8_t *data, uint8_t data_len) {
	memset(buf, 0, HDR_LEN); // Reset header
	memset(buf + HDR_LEN, 0xff, BUF_SIZE - HDR_LEN); // Reset data
	buf[1] = data_len; // Data length
	init_4b(crc32(0L, data, data_len), buf + 4); // Data CRC is at buf[4]
	memcpy(buf + HDR_LEN, data, data_len); // Copy data to buf
}

int camd35_send_ecm(struct camd35 *c, uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t provider_id = 0;
	int to_send = boundary(4, HDR_LEN + data_len);

	camd35_buf_init(c, buf, data, data_len);

	buf[0] = 0x00; // CMD ECM request
	init_2b(service_id , buf + 8);
	init_2b(ca_id      , buf + 10);
	init_4b(provider_id, buf + 12);
	init_2b(idx        , buf + 16);
	buf[18] = 0xff;
	buf[19] = 0xff;

	camd35_send(c, buf, to_send);
	camd35_recv_cw(c);
	return 0;
}

int camd35_send_emm(struct camd35 *c, uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t prov_id = 0;
	int to_send = boundary(4, data_len + HDR_LEN);

	camd35_buf_init(c, buf, data, data_len);

	buf[0] = 0x06; // CMD incomming EMM
	init_2b(ca_id  , buf + 10);
	init_4b(prov_id, buf + 12);

	return camd35_send(c, buf, to_send);
}
