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

static unsigned long crc_table[256] = {
  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
  0x2d02ef8dL
};

#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf) DO1(buf); DO1(buf);
#define DO4(buf) DO2(buf); DO2(buf);
#define DO8(buf) DO4(buf); DO4(buf);

unsigned long crc32(unsigned long crc, const uint8_t *buf, unsigned int len) {
	if (!buf)
		return 0L;
	crc = crc ^ 0xffffffffL;
	while (len >= 8) {
		DO8(buf);
		len -= 8;
	}
	if (len) {
		do {
			DO1(buf);
		} while (--len);
	}
	return crc ^ 0xffffffffL;
}

int32_t boundary(int32_t exp, int32_t n) {
	return ((((n-1) >> exp) + 1) << exp);
}

uint8_t *init_4b(uint32_t val, uint8_t *b) {
	b[0] = (val >> 24) & 0xff;
	b[1] = (val >> 16) & 0xff;
	b[2] = (val >>  8) & 0xff;
	b[3] = (val      ) & 0xff;
	return b;
}

uint8_t *init_4l(uint32_t val, uint8_t *b) {
	b[3] = (val >> 24) & 0xff;
	b[2] = (val >> 16) & 0xff;
	b[1] = (val >>  8) & 0xff;
	b[0] = (val      ) & 0xff;
	return b;
}

uint8_t *init_2b(uint32_t val, uint8_t *b) {
	b[0] = (val >> 8) & 0xff;
	b[1] = (val     ) & 0xff;
	return b;
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


static int camd35_send_ecm(uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t provider_id = 0;
	uint32_t crc = crc32(0L, data, data_len);
	int to_send = boundary(4, HDR_LEN + data_len);

	memset(buf, 0xff, BUF_SIZE);

	memset(buf, 0, HDR_LEN);
	buf[1] = data_len;
	init_4b(crc        , buf + 4);
	init_2b(service_id , buf + 8);
	init_2b(ca_id      , buf + 10);
	init_4b(provider_id, buf + 12);
	init_2b(idx        , buf + 16);
	buf[18] = 0xff;
	buf[19] = 0xff;
	memcpy(buf + HDR_LEN, data, data_len);

	return camd35_send(buf, to_send, TYPE_ECM);
}

static int camd35_send_emm(uint16_t ca_id, uint8_t *data, uint8_t data_len) {
	uint8_t buf[BUF_SIZE];
	uint32_t prov_id = 0;
	uint32_t crc = crc32(0L, data, data_len);
	int to_send = boundary(4, data_len + HDR_LEN);

	memset(buf, 0xff, BUF_SIZE);

	memset(buf, 0, HDR_LEN);
	buf[0] = 0x06;
	buf[1] = data_len;
	init_4b(crc    , buf + 4);
	init_2b(ca_id  , buf + 10);
	init_4b(prov_id, buf + 12);
	memcpy(buf + HDR_LEN, data, data_len);

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
	camd35_test();
	return 0;

	int fd = 0; // stdin

	parse_options(argc, argv);

	struct ts_pat *pat = ts_pat_alloc();
	struct ts_cat *cat = ts_cat_alloc();
	struct ts_pmt *pmt = ts_pmt_alloc();
	struct ts_privsec *emm = ts_privsec_alloc();
	struct ts_privsec *ecm = ts_privsec_alloc();
	struct ts_privsec *last_emm = NULL;
	struct ts_privsec *last_ecm = NULL;
	uint16_t pmt_pid = 0;

	uint16_t emm_caid = 0, emm_pid = 0;
	uint16_t ecm_caid = 0, ecm_pid = 0;
	uint16_t program_id = 0;
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
							program_id = prg->program;
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
				if (req_CA_sys != CA_UNKNOWN)
					ts_get_emm_info(cat, req_CA_sys, &emm_caid, &emm_pid);
				ts_cat_free(&cat);
				cat = ts_cat_alloc();
			}
		}

		if (pid && pid == pmt_pid) {
			pmt = ts_pmt_push_packet(pmt, ts_packet, pmt_pid);
			if (pmt->initialized) {
				if (req_CA_sys != CA_UNKNOWN)
					ts_get_ecm_info(pmt, req_CA_sys, &ecm_caid, &ecm_pid);
				ts_pmt_free(&pmt);
				pmt = ts_pmt_alloc();
			}
		}

		if (0 && emm_pid && pid == emm_pid) {
			emm = ts_privsec_push_packet(emm, ts_packet);
			if (emm->initialized) {
				struct ts_header *th = &emm->ts_header;
				struct ts_section_header *sec = emm->section_header;
				//savefile(sec->section_data, sec->section_length + 3, TYPE_EMM);
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
					//savefile(sec->section_data, sec->section_length + 3, TYPE_ECM);
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

	if (emm_caid) {
		char *CA_sys = ts_get_CA_sys_txt(ts_get_CA_sys(emm_caid));
		printf("%s PRG_id  : 0x%04x\n", CA_sys, program_id);
		printf("%s CA_id   : 0x%04x\n", CA_sys, emm_caid);
		printf("%s EMM pid : 0x%04x\n", CA_sys, emm_pid);
		printf("%s ECM pid : 0x%04x\n", CA_sys, ecm_pid);
	}

	exit(0);
}
