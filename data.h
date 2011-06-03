#ifndef DATA_H
#define DATA_H

#include <openssl/aes.h>
#include <openssl/md5.h>

#include <dvbcsa/dvbcsa.h>

#include "libts/tsfuncs.h"

struct key {
	uint8_t				cw[16];
	int					is_valid_cw;
	struct dvbcsa_key_s	*csakey[2];
};

struct camd35 {
	int				server_fd;
	struct in_addr	server_addr;
	unsigned int	server_port;
	char			user[64];
	char			pass[64];

	AES_KEY			aes_encrypt_key;
	AES_KEY			aes_decrypt_key;

	uint32_t		auth_token;

	struct key		*key;
};

struct ts {
	// Stream handling
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
	pidmap_t			pidmap;

	// CAMD handling
	struct key			key;
	struct camd35		camd35;

	// Config
	enum CA_system		req_CA_sys;

	int					emm_send;
	int					pid_filter;

	struct in_addr		output_addr;
	unsigned int		output_port;
	int					output_ttl;
	struct in_addr		output_intf;

	int					debug_level;
};

void data_init(struct ts *ts);
void data_free(struct ts *ts);

#endif
