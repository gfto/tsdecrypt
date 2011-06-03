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

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"
#include "libts/tsfuncs.h"

#include "util.h"

uint8_t cur_cw[16];
int is_valid_cw = 0;
uint8_t invalid_cw[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
struct dvbcsa_key_s *csakey[2];

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
	ts->pat	     = ts_pat_alloc();
	ts->curpat   = ts_pat_alloc();

	ts->cat      = ts_cat_alloc();
	ts->curcat   = ts_cat_alloc();

	ts->pmt      = ts_pmt_alloc();
	ts->curpmt   = ts_pmt_alloc();

	ts->emm      = ts_privsec_alloc();
	ts->last_emm = ts_privsec_alloc();

	ts->ecm      = ts_privsec_alloc();
	ts->last_ecm = ts_privsec_alloc();
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

unsigned long ts_pack = 0;
int ts_pack_shown = 0;
int debug_level = 0;

static void show_ts_pack(uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet) {
	char cw1_dump[8 * 6];
	char cw2_dump[8 * 6];
	if (debug_level >= 4) {
		if (ts_pack_shown)
			return;
		int stype = ts_packet_get_scrambled(ts_packet);
		ts_hex_dump_buf(cw1_dump, 8 * 6, cur_cw    , 8, 0);
		ts_hex_dump_buf(cw2_dump, 8 * 6, cur_cw + 8, 8, 0);
		fprintf(stderr, "@ %s %s %03x %5ld %7ld | %s   %s | %s\n",
			stype == 0 ? "------" :
			stype == 2 ? "even 0" :
			stype == 3 ? "odd  1" : "??????",
			wtf,
			pid,
			ts_pack, ts_pack * 188,
			cw1_dump, cw2_dump, extra ? extra : wtf);
	}
}

static void dump_ts_pack(uint16_t pid, uint8_t *ts_packet) {
	if (pid == 0x010)		show_ts_pack(pid, "nit", NULL, ts_packet);
	else if (pid == 0x11)	show_ts_pack(pid, "sdt", NULL, ts_packet);
	else if (pid == 0x12)	show_ts_pack(pid, "epg", NULL, ts_packet);
	else					show_ts_pack(pid, "---", NULL, ts_packet);
}

enum CA_system req_CA_sys = CA_CONNAX;
int server_fd = -1;
struct in_addr camd35_server_addr;
unsigned int camd35_server_port = 2233;
char *camd35_user = "user";
char *camd35_pass = "pass";
uint32_t camd35_auth = 0;
AES_KEY camd35_aes_encrypt_key;
AES_KEY camd35_aes_decrypt_key;

int emm_send = 1;
int pid_filter = 1;

struct in_addr output_addr;
unsigned int output_port;
int output_ttl = 1;
struct in_addr output_intf;

void show_help() {
	printf("TSDECRYPT v1.0\n");
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: tsdecrypt [opts] < mpeg_ts\n");
	printf("\n");
	printf("  Options:\n");
	printf("    -c ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(req_CA_sys));
	printf("\n");
	printf("  CAMD35 server options:\n");
	printf("    -s server_addr | default: disabled (format 1.2.3.4:2233)\n");
	printf("    -U server_user | default: %s\n", camd35_user);
	printf("    -P server_pass | default: %s\n", camd35_pass);
	printf("\n");
	printf("  Output options (if output is disabled stdout is used for output):\n");
	printf("    -o output_addr | default: disabled (format: 239.78.78.78:5000)\n");
	printf("    -i output_intf | default: %s\n", inet_ntoa(output_intf));
	printf("    -t output_ttl  | default: %d\n", output_ttl);
	printf("\n");
	printf("  Filtering options:\n");
	printf("    -e             | EMM send (default: %s).\n", emm_send ? "enabled" : "disabled");
	printf("                   | - Send EMMs to CAMD server for processing.\n");
	printf("\n");
	printf("    -p             | Output PID filter (default: %s).\n", pid_filter ? "enabled" : "disabled");
	printf("                   | - When PID filter is enabled only PAT/PMT/SDT/data\n");
	printf("                   | - packets are left in the output.\n");
	printf("\n");
	printf("    -D debug_level | Message debug level. Bigger levels includes the levels bellow.\n");
	printf("                   |    0 - default messages\n");
	printf("                   |    1 - show PSI tables\n");
	printf("                   |    2 - show EMMs\n");
	printf("                   |    3 - show duplicate ECMs\n");
	printf("                   |    4 - packet debug\n");
	printf("\n");
}

void parse_options(int argc, char **argv) {
	int j, ca_err = 0, server_err = 1, output_addr_err = 0, output_intf_err = 0;
	while ((j = getopt(argc, argv, "cFs:o:i:t:U:P:epD:h")) != -1) {
		char *p = NULL;
		switch (j) {
			case 'c':
				if (strcasecmp("IRDETO", optarg) == 0)
					req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0)
					req_CA_sys = CA_CONNAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					req_CA_sys = CA_CRYPTOWORKS;
				else
					ca_err = 1;
				break;

			case 's':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					camd35_server_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &camd35_server_addr) == 0)
					server_err = 1;
				else
					server_err = 0;
				break;

			case 'o':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					output_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &output_addr) == 0)
					output_addr_err = 1;
				break;
			case 'i':
				if (inet_aton(optarg, &output_intf) == 0)
					output_intf_err = 1;
				break;
			case 't':
				output_ttl = atoi(optarg);
				break;

			case 'U':
				camd35_user = optarg;
				break;
			case 'P':
				camd35_pass = optarg;
				break;

			case 'e':
				emm_send = !emm_send;
				break;
			case 'p':
				pid_filter = !pid_filter;
				break;

			case 'D':
				debug_level = atoi(optarg);
				break;

			case 'h':
				show_help();
				exit(0);
		}
	}
	if (ca_err || server_err) {
		show_help();
		if (ca_err)
			fprintf(stderr, "ERROR: Requested CA system is unsupported.\n");
		if (server_err)
			fprintf(stderr, "ERROR: Server IP address is not set or it is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output IP address is invalid.\n");
		if (output_intf_err)
			fprintf(stderr, "ERROR: Output interface address is invalid.\n");
		exit(1);
	}
	ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(req_CA_sys));
	ts_LOGf("Server addr: %s:%u\n", inet_ntoa(camd35_server_addr), camd35_server_port);
	ts_LOGf("Server user: %s\n", camd35_user);
	ts_LOGf("Server pass: %s\n", camd35_pass);
	if (output_port) {
		ts_LOGf("Output addr: %s:%u\n", inet_ntoa(output_addr), output_port);
		ts_LOGf("Output intf: %s\n", inet_ntoa(output_intf));
		ts_LOGf("Output ttl : %d\n", output_ttl);
	}
	ts_LOGf("EMM send   : %s\n", emm_send   ? "enabled" : "disabled");
	ts_LOGf("PID filter : %s\n", pid_filter ? "enabled" : "disabled");
}

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
		server_fd = connect_to(camd35_server_addr, camd35_server_port);
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

#define ERR(x) do { ts_LOGf("%s", x); return NULL; } while (0)

static uint8_t *camd35_recv_cw() {
	uint8_t data[BUF_SIZE];
	int data_len = 0;

NEXT:
	if (camd35_recv(data, &data_len) < 0)
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
	memcpy(cur_cw, cw, 16);

	char cw_dump[16 * 6];
	ts_hex_dump_buf(cw_dump, 16 * 6, cw, 16, 0);
	ts_LOGf("CW  | CAID: 0x%04x ---------------------------------- IDX: 0x%04x Data: %s\n", ca_id, idx, cw_dump);

	is_valid_cw = valid_cw(cur_cw);
	dvbcsa_key_set(cur_cw    , csakey[0]);
	dvbcsa_key_set(cur_cw + 8, csakey[1]);

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
		show_ts_pack(pid, #TABLE, NULL, ts_packet); \
		ts->cur##TABLE = ts_##TABLE##_push_packet(ts->cur##TABLE, ts_packet); \
		if (!ts->cur##TABLE->initialized) \
			return;  \
		if (ts_##TABLE##_is_same(ts->TABLE, ts->cur##TABLE)) { \
			ts_##TABLE##_clear(ts->cur##TABLE); \
			return; \
		} \
		ts_##TABLE##_free(&ts->TABLE); \
		ts->TABLE = ts_##TABLE##_copy(ts->cur##TABLE); \
		ts_##TABLE##_clear(ts->cur##TABLE); \
		if (debug_level >= 1) \
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

#define dump_sz      (16)
#define dump_buf_sz  (dump_sz * 6)

void process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];
	if (!ts->emm_pid || ts->emm_pid != pid)
		return;

	show_ts_pack(pid, "emm", NULL, ts_packet);

	if (!emm_send)
		return;

	ts->emm = ts_privsec_push_packet(ts->emm, ts_packet);
	if (!ts->emm->initialized)
		return;

	struct ts_header *th = &ts->emm->ts_header;
	struct ts_section_header *sec = ts->emm->section_header;
	if (debug_level >= 2) {
		ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
		ts_LOGf("EMM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d ----------- Data: %s..\n",
			ts->emm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			dump);
	}
	camd35_send_emm(ts->emm_caid, sec->section_data, sec->section_data_len);
	ts_privsec_copy(ts->emm, ts->last_emm);
	ts_privsec_clear(ts->emm);
}

void process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	char dump[dump_buf_sz];
	if (!ts->ecm_pid || ts->ecm_pid != pid)
		return;

	ts->ecm = ts_privsec_push_packet(ts->ecm, ts_packet);
	if (!ts->ecm->initialized)
		return;

	struct ts_header *th = &ts->ecm->ts_header;
	struct ts_section_header *sec = ts->ecm->section_header;
	int duplicate = ts_privsec_is_same(ts->ecm, ts->last_ecm);
	if (!duplicate) {
		ts_hex_dump_buf(dump, dump_buf_sz, sec->section_data, min(dump_sz, sec->section_data_len), 0);
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d IDX: 0x%04x Data: %s..\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			ts->ecm_counter,
			dump);
		camd35_send_ecm(ts->service_id, ts->ecm_caid, ts->ecm_counter++, sec->section_data, sec->section_data_len);
	} else if (debug_level >= 3) {
		ts_LOGf("ECM | CAID: 0x%04x PID 0x%04x Table: 0x%02x Length: %3d IDX: 0x%04x Data: -dup-\n",
			ts->ecm_caid,
			th->pid,
			sec->table_id,
			sec->section_data_len,
			ts->ecm_counter - 1);
	}
	ts_privsec_copy(ts->ecm, ts->last_ecm);
	ts_privsec_clear(ts->ecm);

	show_ts_pack(pid, !duplicate ? "ecm" : "ec+", NULL, ts_packet);
}

void ts_process_packets(struct ts *ts, uint8_t *data, ssize_t data_len) {
	ssize_t i;
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);

		ts_pack_shown = 0;

		process_pat(ts, pid, ts_packet);
		process_cat(ts, pid, ts_packet);
		process_pmt(ts, pid, ts_packet);
		process_emm(ts, pid, ts_packet);
		process_ecm(ts, pid, ts_packet);

		if (!ts_pack_shown)
			dump_ts_pack(pid, ts_packet);

		int scramble_idx = ts_packet_get_scrambled(ts_packet);
		if (scramble_idx > 1) {
			if (is_valid_cw) {
				// scramble_idx 2 == even key
				// scramble_idx 3 == odd key
				ts_packet_set_not_scrambled(ts_packet);
				dvbcsa_decrypt(csakey[scramble_idx - 2], ts_packet + 4, 184);
			}
		}

		ts_pack++;
	}
}

void ts_write_packets(struct ts *ts, uint8_t *data, ssize_t data_len) {
	ts = ts;
	write(1, data, data_len);
	return;
/*
	ssize_t i;
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);
		write(1, ts_packet, 188);
	}
*/
}

#define FRAME_SIZE (188 * 7)

int main(int argc, char **argv) {
	ssize_t readen;
	uint8_t ts_packet[FRAME_SIZE];

	csakey[0] = dvbcsa_key_alloc();
	csakey[1] = dvbcsa_key_alloc();

	memset(cur_cw, 0, sizeof(cur_cw));
	ts_set_log_func(LOG_func);

	parse_options(argc, argv);

	camd35_connect();

	struct ts *ts = ts_alloc();
	do {
		readen = read(0, ts_packet, FRAME_SIZE);
		if (readen > 0) {
			ts_process_packets(ts, ts_packet, readen);
			ts_write_packets(ts, ts_packet, readen);
		}
	} while (readen > 0);
	ts_free(&ts);

	dvbcsa_key_free(csakey[0]);
	dvbcsa_key_free(csakey[1]);

	shutdown_fd(&server_fd);
	exit(0);
}
