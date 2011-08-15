#ifndef DATA_H
#define DATA_H

#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/md5.h>

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"
#include "libts/tsfuncs.h"

#include "cbuf.h"

// 7 * 188
#define FRAME_SIZE 1316

// How much seconds to assume the key is valid
#define KEY_VALID_TIME 10

struct key {
	uint8_t				cw[16];
	int					is_valid_cw;
	struct dvbcsa_key_s	*csakey[2];
	struct dvbcsa_bs_key_s	*bs_csakey[2];
	time_t				ts;	// At what time the key is set
};

// 4 auth header, 20 header size, 256 max data size, 16 potential padding
#define CAMD35_HDR_LEN (20)
#define CAMD35_BUF_LEN (4 + CAMD35_HDR_LEN + 256 + 16)

struct camd35 {
	uint8_t			buf[CAMD35_BUF_LEN];

	int				server_fd;
	struct in_addr	server_addr;
	unsigned int	server_port;
	char			user[64];
	char			pass[64];

	int				emm_count;
	int				emm_count_report_interval;
	time_t			emm_count_last_report;

	AES_KEY			aes_encrypt_key;
	AES_KEY			aes_decrypt_key;

	uint32_t		auth_token;

	struct key		*key;

	pthread_t		thread;
	QUEUE			*queue;
};

enum io_type {
	FILE_IO,
	NET_IO,
	WTF_IO
};

struct io {
	int					fd;
	enum io_type		type;
	char				*fname;
	struct in_addr		addr;
	unsigned int		port;
	// Used only for output
	int					ttl;
	struct in_addr		intf;
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
	pidmap_t			cc; // Continuity counters
	pidmap_t			pid_seen;

	// CAMD handling
	struct key			key;
	struct camd35		camd35;

	// Config
	char				ident[128];
	char				syslog_host[128];
	int					syslog_port;
	int					syslog_active;

	int					daemonize;
	char				pidfile[PATH_MAX];

	enum CA_system		req_CA_sys;

	int					emm_send;
	int					pid_filter;

	struct io			input;
	struct io			output;

	int					debug_level;
	int					ts_discont;

	int					camd_stop;
	int					is_cw_error;

	int					threaded;

	int					packet_delay;

	int					decode_stop;
	pthread_t			decode_thread;
	CBUF				*decode_buf;

	int					write_stop;
	pthread_t			write_thread;
	CBUF				*write_buf;
};

enum msg_type { EMM_MSG, ECM_MSG };

struct camd_msg {
	enum msg_type	type;
	uint16_t		idx;
	uint16_t		ca_id;
	uint16_t		service_id;
	uint8_t			data_len;
	uint8_t			data[255];
	struct ts		*ts;
};

void data_init(struct ts *ts);
void data_free(struct ts *ts);

#endif
