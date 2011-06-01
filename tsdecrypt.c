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

#include <openssl/aes.h>
#include <openssl/md5.h>

#include "libts/tsfuncs.h"

#include "util.h"

enum CA_system req_CA_sys = CA_CONNAX;
char *camd35_user = "user";
char *camd35_pass = "pass";
uint32_t camd35_auth = 0;
AES_KEY camd35_aes_encrypt_key;
AES_KEY camd35_aes_decrypt_key;

void show_help() {
	printf("TSCRYPT v1.0\n");
	puts("Copyright (c) 2011 Unix Solutions Ltd.");
	puts("");
	puts("	Usage: tsdecrypt [opts] < data > data.decrypted");
	puts("");
	exit(0);
}

void parse_options(int argc, char **argv) {
	int j;
	while ((j = getopt(argc, argv, "f:h")) != -1) {
		switch (j) {
			case 'h':
				show_help();
				exit(0);
		}
	}
}

enum e_flag {
	TYPE_EMM,
	TYPE_ECM
};

void savefile(uint8_t *data, int datasize, enum e_flag flag) {
	static int cnt = 0;
	char *fname;
	asprintf(&fname, "%03d-%s.dump", ++cnt, flag == TYPE_EMM ? "emm" : "ecm");
	int fd = open(fname, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	write(fd, data, datasize);
	close(fd);
	free(fname);
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

static int camd35_recv(uint8_t *data, int *data_len) {
	int i;

	uint32_t auth_token = (((data[0] << 24) | (data[1] << 16) | (data[2]<<8) | data[3]) & 0xffffffffL);
	if (auth_token != camd35_auth)
		fprintf(stderr, "WARN: recv auth : 0x%08x != camd35_auth 0x%08x\n", auth_token, camd35_auth);

	*data_len -= 4; // Remove header
	memmove(data, data + 4, *data_len); // Remove header

	for (i = 0; i < *data_len; i += 16) // Decrypt payload
		AES_decrypt(data + i, data + i, &camd35_aes_decrypt_key);

	return 0;
}

static int camd35_send(uint8_t *data, uint8_t data_len, enum e_flag tp) {
	unsigned int i;
	uint8_t buf[BUF_SIZE];
	uint8_t *bdata = buf + 4;

	init_4b(camd35_auth, buf); // Put authentication token
	memcpy(bdata, data, data_len); // Put data

	for (i = 0; i < data_len; i += 16) // Encrypt payload
		AES_encrypt(data + i, bdata + i, &camd35_aes_encrypt_key);

	savefile(buf, data_len + 4, tp);

	return 0;
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

	return camd35_send(buf, to_send, TYPE_ECM);
}

static int camd35_send_emm(uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t prov_id = 0;
	int to_send = boundary(4, data_len + HDR_LEN);

	camd35_buf_init(buf, data, data_len);

	buf[0] = 0x06; // CMD incomming EMM
	init_2b(ca_id  , buf + 10);
	init_4b(prov_id, buf + 12);

	return camd35_send(buf, to_send, TYPE_EMM);
}

#define ERR(x) do { fprintf(stderr, "%s", x); return NULL; } while (0)

static uint8_t *camd35_recv_cw(uint8_t *data, int data_len) {
	char *d;

	camd35_recv(data, &data_len);

	if (data_len < 48)
		ERR("len mismatch != 48");

	if (data[0] < 0x01)
		ERR("Not valid CW response");

	if (data[1] < 0x10)
		ERR("CW len mismatch != 0x10");

	d = ts_hex_dump(data, data_len, 16);
	fprintf(stderr, "Recv CW :\n%s\n", d);
	free(d);

	uint16_t ca_id = (data[10] << 8) | data[11];
	uint16_t idx   = (data[16] << 8) | data[17];
	fprintf(stderr, "CW ca_id: 0x%04x\n", ca_id);
	fprintf(stderr, "CW idx  : 0x%04x\n", idx);

	d = ts_hex_dump(data + 20, 16, 0);
	fprintf(stderr, "CW      : %s\n", d);
	free(d);

	return data + 20;
}

#undef ERR

void camd35_test() {
	#define test_ecm_len 103
	uint8_t test_ecm[test_ecm_len] = {
		 0x80, 0x70, 0x64, 0x70, 0x62, 0x64, 0x20, 0x76, 0xFF, 0xA8, 0xC1, 0x80, 0x9C, 0xE3, 0xDC, 0xB4, 
		 0xD9, 0xC3, 0xD1, 0xEA, 0x26, 0xFE, 0xF7, 0xE4, 0xA8, 0x26, 0x34, 0x45, 0x51, 0x82, 0x6A, 0xE0, 
		 0x00, 0x37, 0x09, 0x1A, 0xAE, 0xC3, 0x5A, 0xD6, 0xE1, 0xC1, 0x5F, 0x8E, 0x55, 0xC3, 0xA4, 0x88, 
		 0x38, 0x93, 0xDC, 0xD5, 0x9F, 0x10, 0x58, 0xC0, 0xED, 0xB8, 0x4C, 0xED, 0x19, 0x6A, 0x2A, 0xEF, 
		 0x6D, 0xCB, 0x9F, 0x7B, 0x71, 0xC4, 0x29, 0x44, 0x7F, 0xA0, 0x76, 0x80, 0x9E, 0x29, 0x52, 0x4E, 
		 0x19, 0x11, 0xC4, 0xCD, 0xFD, 0x8F, 0x4F, 0xEC, 0x7F, 0x6A, 0xE3, 0x1F, 0x1F, 0x24, 0x0D, 0xEE, 
		 0x7F, 0xF2, 0x35, 0xA4, 0x1C, 0x86, 0x84 };

	#define test_recv_len 128
	uint8_t test_recv[test_recv_len] = {
		 0x00, 0x67, 0x00, 0x00, 0x99, 0x14, 0x7A, 0xA0, 0x15, 0x22, 0x0B, 0x01, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x12, 0xFF, 0xFF, 0x80, 0x70, 0x64, 0x70, 0x62, 0x64, 0x20, 0x76, 0xFF, 0xA8, 0xC1, 0x80,
		 0x9C, 0xE3, 0xDC, 0xB4, 0xD9, 0xC3, 0xD1, 0xEA, 0x26, 0xFE, 0xF7, 0xE4, 0xA8, 0x26, 0x34, 0x45,
		 0x51, 0x82, 0x6A, 0xE0, 0x00, 0x37, 0x09, 0x1A, 0xAE, 0xC3, 0x5A, 0xD6, 0xE1, 0xC1, 0x5F, 0x8E,
		 0x55, 0xC3, 0xA4, 0x88, 0x38, 0x93, 0xDC, 0xD5, 0x9F, 0x10, 0x58, 0xC0, 0xED, 0xB8, 0x4C, 0xED,
		 0x19, 0x6A, 0x2A, 0xEF, 0x6D, 0xCB, 0x9F, 0x7B, 0x71, 0xC4, 0x29, 0x44, 0x7F, 0xA0, 0x76, 0x80,
		 0x9E, 0x29, 0x52, 0x4E, 0x19, 0x11, 0xC4, 0xCD, 0xFD, 0x8F, 0x4F, 0xEC, 0x7F, 0x6A, 0xE3, 0x1F,
		 0x1F, 0x24, 0x0D, 0xEE, 0x7F, 0xF2, 0x35, 0xA4, 0x1C, 0x86, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	#define test_recv_cw_len 52
	uint8_t test_recv_cw[test_recv_cw_len] = {
		 0x11, 0x22, 0x33, 0x44,
		 0x01, 0x10, 0x00, 0x00, 0xB2, 0x05, 0xDF, 0xA0, 0x15, 0x22, 0x0B, 0x01, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x12, 0xFF, 0xFF, 0xE1, 0x96, 0xE6, 0x5D, 0x09, 0x83, 0x91, 0x1D, 0x85, 0xA4, 0xD1, 0xFA,
		 0xB7, 0x43, 0xAA, 0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	camd35_init_auth(camd35_user, camd35_pass);

	char *d = ts_hex_dump(test_recv, test_recv_len, 16);
	fprintf(stderr, "%s\n\n", d);
	free(d);

	camd35_send_ecm(0x1522, 0x0b01, 0x0012, test_ecm, test_ecm_len);

//	camd35_send_emm(0x0b01, test_ecm, test_ecm_len);
//
//	camd35_recv_cw(test_recv_cw, test_recv_cw_len);
}


int main(int argc, char **argv) {
	int fd = 0; // stdin

	parse_options(argc, argv);

	camd35_init_auth(camd35_user, camd35_pass);

	struct ts_pat *pat = ts_pat_alloc();
	struct ts_cat *cat = ts_cat_alloc();
	struct ts_pmt *pmt = ts_pmt_alloc();
	struct ts_privsec *emm = ts_privsec_alloc();
	struct ts_privsec *ecm = ts_privsec_alloc();
	struct ts_privsec *last_emm = NULL;
	struct ts_privsec *last_ecm = NULL;
	uint16_t pmt_pid = 0;

	uint16_t ca_id = 0;
	uint16_t emm_caid = 0, emm_pid = 0;
	uint16_t ecm_caid = 0, ecm_pid = 0;
	uint16_t service_id = 0;
	uint16_t ecm_counter = 0;

	do {
		uint8_t ts_packet[188];
		ssize_t readen = read(fd, ts_packet, 188);
		if (readen < 188)
			break;

		uint16_t pid = ts_packet_get_pid(ts_packet);

		if (pid == 0x00) {
			pat = ts_pat_push_packet(pat, ts_packet);
			if (pat->initialized) {
				int i;
				for (i=0;i<pat->programs_num;i++) {
					struct ts_pat_program *prg = pat->programs[i];
					if (prg->pid) {
						if (prg->program != 0) {
							service_id = prg->program;
							pmt_pid = prg->pid;
						}
					}
				}
				ts_pat_free(&pat);
				pat = ts_pat_alloc();
			}
		}

		if (pid == 1) {
			cat = ts_cat_push_packet(cat, ts_packet);
			if (cat->initialized) {
				if (req_CA_sys != CA_UNKNOWN) {
					ts_get_emm_info(cat, req_CA_sys, &emm_caid, &emm_pid);
					ca_id = emm_caid;
				}
				ts_cat_free(&cat);
				cat = ts_cat_alloc();
			}
		}

		if (pid && pid == pmt_pid) {
			pmt = ts_pmt_push_packet(pmt, ts_packet, pmt_pid);
			if (pmt->initialized) {
				if (req_CA_sys != CA_UNKNOWN && !ecm_caid) {
					ts_get_ecm_info(pmt, req_CA_sys, &ecm_caid, &ecm_pid);
					char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(emm_caid));
					printf("%s Service : 0x%04x\n", CA_sys, service_id);
					printf("%s CA_id   : 0x%04x\n", CA_sys, emm_caid);
					printf("%s EMM pid : 0x%04x\n", CA_sys, emm_pid);
					printf("%s ECM pid : 0x%04x\n", CA_sys, ecm_pid);
				}
				ts_pmt_free(&pmt);
				pmt = ts_pmt_alloc();
			}
		}

		if (emm_pid && pid == emm_pid) {
			emm = ts_privsec_push_packet(emm, ts_packet);
			if (emm->initialized) {
				struct ts_header *th = &emm->ts_header;
				struct ts_section_header *sec = emm->section_header;
				camd35_send_emm(ca_id, sec->section_data, sec->section_length + 3);
				char *data = ts_hex_dump(sec->section_data, sec->section_length, 0);
				ts_LOGf("EMM dump | CAID: 0x%04x PID 0x%04x (%5d) Table: 0x%02x (%3d) Length: %4d Data: %s\n",
					emm_caid,
					th->pid, th->pid,
					sec->table_id, sec->table_id,
					sec->section_length + 3,
					data);
				FREE(data);
				ts_privsec_free(&last_emm);
				last_emm = emm;
				emm = ts_privsec_alloc();
			}
		}

#ifndef min
#define min(a,b) ((a < b) ? a : b)
#endif

		if (ecm_pid && pid == ecm_pid) {
			ecm = ts_privsec_push_packet(ecm, ts_packet);
			if (ecm->initialized) {
				int is_same = 0;
				struct ts_header *th = &ecm->ts_header;
				struct ts_section_header *sec = ecm->section_header;
				if (last_ecm) {
					is_same = memcmp(
						last_ecm->section_header->section_data,
						ecm->section_header->section_data,
						min(last_ecm->section_header->section_length, ecm->section_header->section_length)) == 0;
				}
				if (!is_same) {
					camd35_send_ecm(service_id, ca_id, ecm_counter++, sec->section_data, sec->section_length + 3);
					char *data = ts_hex_dump(sec->section_data, sec->section_length, 0);
					ts_LOGf("ECM dump | CAID: 0x%04x PID 0x%04x (%5d) Table: 0x%02x (%3d) Length: %4d Data: %s\n",
						ecm_caid,
						th->pid, th->pid,
						sec->table_id, sec->table_id,
						sec->section_length + 3,
						data);
					FREE(data);
				} else if (0) {
					ts_LOGf("ECM dump | CAID: 0x%04x PID 0x%04x (%5d) Table: 0x%02x (%3d) Length: %4d Data: --duplicate--\n",
						ecm_caid,
						th->pid, th->pid,
						sec->table_id, sec->table_id,
						sec->section_length + 3);
				}
				ts_privsec_free(&last_ecm);
				last_ecm = ecm;
				ecm = ts_privsec_alloc();
			}
		}
	} while (1);
	ts_pat_free(&pat);
	ts_cat_free(&cat);
	ts_pmt_free(&pmt);
	ts_privsec_free(&emm);
	ts_privsec_free(&ecm);
	ts_privsec_free(&last_emm);
	ts_privsec_free(&last_ecm);


	exit(0);
}
