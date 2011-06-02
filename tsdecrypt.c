#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sched.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/md5.h>

#include "libfuncs/libfuncs.h"
#include "libts/tsfuncs.h"

#include "util.h"

uint8_t cur_cw[16];
uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static inline int valid_cw(uint8_t *cw) {
	return memcmp(cw, invalid_cw, 16) != 0;
}


struct ts {
	struct ts_pat		*pat, *curpat;
	struct ts_cat		*cat, *curcat;
	struct ts_pmt		*pmt, *curpmt;
	struct ts_privsec	*emm, *last_emm;
	struct ts_privsec	*ecm, *last_ecm;
	uint16_t			pmt_pid;
	uint16_t			service_id;
	uint16_t			emm_caid, emm_pid;
	uint16_t			ecm_caid, ecm_pid;
	uint16_t			ecm_counter;
};

struct ts *ts_alloc() {
	struct ts *ts = calloc(1, sizeof(struct ts));
	return ts;
}

void ts_free(struct ts **pts) {
	struct ts *ts = *pts;
	if (ts) {
		ts_pat_free(&ts->pat);
		ts_pat_free(&ts->curpat);
		ts_cat_free(&ts->cat);
		ts_cat_free(&ts->curcat);
		ts_pmt_free(&ts->pmt);
		ts_pmt_free(&ts->curpmt);
		ts_privsec_free(&ts->emm);
		ts_privsec_free(&ts->last_emm);
		ts_privsec_free(&ts->ecm);
		ts_privsec_free(&ts->last_ecm);
		FREE(*pts);
	}
}

void LOG_func(const char *msg) {
	char date[64];
	struct tm tm;
	time_t now;
	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime(&now));
	fprintf(stderr, "%s | %s", date, msg);
}

enum CA_system req_CA_sys = CA_CONNAX;
int server_fd = -1;
char *camd35_server = "10.0.1.78";
struct in_addr camd35_server_ip;
uint16_t camd35_port = 2233;
char *camd35_user = "user";
char *camd35_pass = "pass";
uint32_t camd35_auth = 0;
AES_KEY camd35_aes_encrypt_key;
AES_KEY camd35_aes_decrypt_key;

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

static void camd35_init_auth(char *user, char *pass) {
	unsigned char dump[16];
	camd35_auth = crc32(0L, MD5((unsigned char *)user, strlen(user), dump), 16);

	MD5((unsigned char *)pass, strlen(pass), dump);

	AES_set_encrypt_key(dump, 128, &camd35_aes_encrypt_key);
	AES_set_decrypt_key(dump, 128, &camd35_aes_decrypt_key);
}

static void camd35_connect() {
	if (server_fd < 0)
		server_fd = connect_to(camd35_server_ip, camd35_port);
}

static int camd35_recv(uint8_t *data, int *data_len) {
	int i;

	// Read AUTH token
	ssize_t r = fdread(server_fd, (char *)data, 4);
	if (r < 4)
		return -1;
	uint32_t auth_token = (((data[0] << 24) | (data[1] << 16) | (data[2]<<8) | data[3]) & 0xffffffffL);
	if (auth_token != camd35_auth)
		ts_LOGf("WARN: recv auth 0x%08x != camd35_auth 0x%08x\n", auth_token, camd35_auth);

	*data_len = 256;
	for (i = 0; i < *data_len; i += 16) { // Read and decrypt payload
		fdread(server_fd, (char *)data + i, 16);
		AES_decrypt(data + i, data + i, &camd35_aes_decrypt_key);
		if (i == 0)
			*data_len = boundary(4, data[1] + 20); // Initialize real data length
	}
	return *data_len;
}

#define ERR(x) do { fprintf(stderr, "%s", x); return NULL; } while (0)

static uint8_t *camd35_recv_cw() {
	uint8_t data[BUF_SIZE];
	int data_len = 0;

NEXT:
	if (camd35_recv(data, &data_len) < 0)
		ERR("No data!");

	if (data_len < 48)
		ERR("len mismatch != 48");

	if (data[0] < 0x01) {
		ts_LOGf("Not valid CW response, skipping it. data[0] = 0x%02x\n", data[0]);
		goto NEXT;
	}

	if (data[1] < 0x10)
		ERR("CW len mismatch != 0x10");

	uint16_t ca_id = (data[10] << 8) | data[11];
	uint16_t idx   = (data[16] << 8) | data[17];
	uint8_t *cw = data + 20;
	memcpy(cur_cw, cw, 16);

	char cw_dump[16 * 6];
	ts_hex_dump_buf(cw_dump, 16 * 6, cw, 16, 0);
	ts_LOGf("CW  | CAID: 0x%04x ---------------------------------- IDX: 0x%04x Data: %s\n", ca_id, idx, cw_dump);

	return NULL;
}

#undef ERR


static int camd35_send(uint8_t *data, uint8_t data_len) {
	unsigned int i;
	uint8_t buf[BUF_SIZE];
	uint8_t *bdata = buf + 4;

	camd35_connect();

	if (!camd35_auth)
		camd35_init_auth(camd35_user, camd35_pass);

	init_4b(camd35_auth, buf); // Put authentication token
	memcpy(bdata, data, data_len); // Put data

	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(data + i, bdata + i, &camd35_aes_encrypt_key);

	return fdwrite(server_fd, (char *)buf, data_len + 4);
}

static void camd35_buf_init(uint8_t *buf, uint8_t *data, uint8_t data_len) {
	memset(buf, 0, HDR_LEN); // Reset header
	memset(buf + HDR_LEN, 0xff, BUF_SIZE - HDR_LEN); // Reset data
	buf[1] = data_len; // Data length
	init_4b(crc32(0L, data, data_len), buf + 4); // Data CRC is at buf[4]
	memcpy(buf + HDR_LEN, data, data_len); // Copy data to buf
}

static int camd35_send_ecm(uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t provider_id = 0;
	int to_send = boundary(4, HDR_LEN + data_len);

	camd35_buf_init(buf, data, data_len);

	buf[0] = 0x00; // CMD ECM request
	init_2b(service_id , buf + 8);
	init_2b(ca_id      , buf + 10);
	init_4b(provider_id, buf + 12);
	init_2b(idx        , buf + 16);
	buf[18] = 0xff;
	buf[19] = 0xff;

	camd35_send(buf, to_send);
	camd35_recv_cw();
	return 0;
}

static int camd35_send_emm(uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t prov_id = 0;
	int to_send = boundary(4, data_len + HDR_LEN);

	camd35_buf_init(buf, data, data_len);

	buf[0] = 0x06; // CMD incomming EMM
	init_2b(ca_id  , buf + 10);
	init_4b(prov_id, buf + 12);

	return camd35_send(buf, to_send);
}

#define handle_table_changes(TABLE) \
	do { \
		if (!ts->cur##TABLE) \
			ts->cur##TABLE = ts_##TABLE##_alloc(); \
		ts->cur##TABLE = ts_##TABLE##_push_packet(ts->cur##TABLE, ts_packet); \
		if (!ts->cur##TABLE->initialized) \
			return;  \
		if (ts_##TABLE##_is_same(ts->TABLE, ts->cur##TABLE)) { \
			ts_##TABLE##_free(&ts->cur##TABLE); \
			return; \
		} \
		ts_##TABLE##_free(&ts->TABLE); \
		ts->TABLE = ts->cur##TABLE; \
		ts->cur##TABLE = NULL; \
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

	ts_get_emm_info(ts->cat, req_CA_sys, &ts->emm_caid, &ts->emm_pid);
}

void process_pmt(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (!pid || pid != ts->pmt_pid)
		return;

	handle_table_changes(pmt);

	if (!ts->ecm_caid) {
		ts_get_ecm_info(ts->pmt, req_CA_sys, &ts->ecm_caid, &ts->ecm_pid);
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(ts->ecm_caid));
		ts_LOGf("%s Service : 0x%04x\n", CA_sys, ts->service_id);
		ts_LOGf("%s CA_id   : 0x%04x\n", CA_sys, ts->emm_caid);
		ts_LOGf("%s EMM pid : 0x%04x\n", CA_sys, ts->emm_pid);
		ts_LOGf("%s ECM pid : 0x%04x\n", CA_sys, ts->ecm_pid);
	}
}

void process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (!ts->emm_pid || ts->emm_pid != pid)
		return;

	if (!ts->emm)
		ts->emm = ts_privsec_alloc();

	ts->emm = ts_privsec_push_packet(ts->emm, ts_packet);
	if (!ts->emm->initialized)
		return;

	struct ts_header *th = &ts->emm->ts_header;
	struct ts_section_header *sec = ts->emm->section_header;
	camd35_send_emm(ts->emm_caid, sec->section_data, sec->section_length + 3);
	char *data = ts_hex_dump(sec->section_data, 16, 0);
	ts_LOGf("EMM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d Data: %s..\n",
		ts->emm_caid,
		th->pid,
		sec->table_id,
		sec->section_length + 3,
		data);
	FREE(data);
	ts_privsec_free(&ts->last_emm);
	ts->last_emm = ts->emm;
	ts->emm = ts_privsec_alloc();
}

void process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (!ts->ecm_pid || ts->ecm_pid != pid)
		return;

	if (!ts->ecm)
		ts->ecm = ts_privsec_alloc();

	ts->ecm = ts_privsec_push_packet(ts->ecm, ts_packet);
	if (!ts->ecm->initialized)
		return;

	struct ts_header *th = &ts->ecm->ts_header;
	struct ts_section_header *sec = ts->ecm->section_header;
	if (!ts_privsec_is_same(ts->ecm, ts->last_ecm)) {
		camd35_send_ecm(ts->service_id, ts->ecm_caid, ts->ecm_counter++, sec->section_data, sec->section_length + 3);
		char *data = ts_hex_dump(sec->section_data, 16, 0);
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d Data: %s..\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_length + 3,
			data);
		FREE(data);
	} else {
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d Data: --duplicate--\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_length + 3);
	}
	ts_privsec_free(&ts->last_ecm);
	ts->last_ecm = ts->ecm;
	ts->ecm = ts_privsec_alloc();
}

void ts_process_packets(struct ts *ts, uint8_t *data, uint8_t data_len) {
	int i;
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);

		process_pat(ts, pid, ts_packet);
		process_cat(ts, pid, ts_packet);
		process_pmt(ts, pid, ts_packet);
		process_emm(ts, pid, ts_packet);
		process_ecm(ts, pid, ts_packet);
	}
}


void show_help() {
	printf("TSDECRYPT v1.0\n");
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: tsdecrypt [opts] < mpeg_ts > mpeg_ts.decrypted\n");
	printf("\n");
	printf("  Options:\n");
	printf("    -C ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(req_CA_sys));
	printf("\n");
	printf("  Server options:\n");
	printf("    -S server_ip   | default: %s\n", camd35_server);
	printf("    -P server_port | default: %u\n", (unsigned int)camd35_port);
	printf("    -u server_user | default: %s\n", camd35_user);
	printf("    -p server_pass | default: %s\n", camd35_pass);
	printf("\n");
	exit(0);
}

void parse_options(int argc, char **argv) {
	int j, ca_err = 0, server_err = 0;
	inet_aton(camd35_server, &camd35_server_ip);
	while ((j = getopt(argc, argv, "C:S:P:u:p:h")) != -1) {
		switch (j) {
			case 'C':
				if (strcasecmp("IRDETO", optarg) == 0)
					req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0)
					req_CA_sys = CA_CONNAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					req_CA_sys = CA_CRYPTOWORKS;
				else
					ca_err = 1;
				break;
			case 'S':
				camd35_server = optarg;
				if (inet_aton(camd35_server, &camd35_server_ip) == 0)
					server_err = 1;
				break;
			case 'P':
				camd35_port = atoi(optarg);
				break;
			case 'u':
				camd35_user = optarg;
				break;
			case 'p':
				camd35_pass = optarg;
				break;
			case 'h':
				show_help();
				exit(0);
		}
	}
	if (ca_err || server_err) {
		if (ca_err)
			fprintf(stderr, "ERROR: Unknown CA\n");
		if (server_err)
			fprintf(stderr, "ERROR: Invalid server IP address\n");
		fprintf(stderr, "\n");
		show_help();
		exit(1);
	}
	fprintf(stderr, "CA System : %s\n", ts_get_CA_sys_txt(req_CA_sys));
	fprintf(stderr, "Server\n");
	fprintf(stderr, "  Addr    : %s:%d\n", inet_ntoa(camd35_server_ip), camd35_port);
	fprintf(stderr, "  Auth    : %s / %s\n", camd35_user, camd35_pass);
	camd35_connect();
}

#define FRAME_SIZE (188 * 7)

int main(int argc, char **argv) {
	ssize_t readen;
	uint8_t ts_packet[FRAME_SIZE];

	memset(cur_cw, 0, sizeof(cur_cw));
	ts_set_log_func(LOG_func);

	parse_options(argc, argv);

	struct ts *ts = ts_alloc();
	do {
		readen = read(0, ts_packet, FRAME_SIZE);
		ts_process_packets(ts, ts_packet, readen);
	} while (readen == FRAME_SIZE);
	ts_free(&ts);

	shutdown_fd(&server_fd);
	exit(0);
}
