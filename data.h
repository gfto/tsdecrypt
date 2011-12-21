/*
 * Data definitions
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
#ifndef DATA_H
#define DATA_H

#include <pthread.h>
#include <limits.h>

#include <openssl/aes.h>
#include <openssl/md5.h>

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"
#include "libtsfuncs/tsfuncs.h"

// 7 * 188
#define FRAME_SIZE 1316

// How much seconds to assume the key is valid
#define KEY_VALID_TIME 10

struct notify {
	pthread_t	thread;				/* Thread handle */
	QUEUE		*notifications;		/* Notification queue */
	char		ident[512];			/* tsdecrypt ident (set by -i) */
	char		program[512];		/* What program to exec */
};

struct key {
	uint8_t				cw[16];
	int					is_valid_cw;
	struct dvbcsa_key_s	*csakey[2];
	struct dvbcsa_bs_key_s	*bs_csakey[2];
	time_t					ts;				// At what time the key is set
	struct timeval			ts_keyset;		// At what time the key is set
};

// 4 auth header, 20 header size, 256 max data size, 16 potential padding
#define CAMD35_HDR_LEN (20)
#define CAMD35_BUF_LEN (4 + CAMD35_HDR_LEN + 256 + 16)

// When this limit is reached invalid_cw flag is set.
#define ECM_RECV_ERRORS_LIMIT 10

// When this limit is reached camd_reconnect is called.
#define EMM_RECV_ERRORS_LIMIT 100

struct camd;
struct ts;

enum msg_type { EMM_MSG, ECM_MSG };

struct camd_msg {
	enum msg_type	type;
	uint16_t		ca_id;
	uint16_t		service_id;
	uint8_t			data_len;
	uint8_t			data[255];
	struct ts		*ts;
};

enum camd_proto {
	CAMD_CS378X,
};

struct camd_ops {
	char ident[16];
	enum camd_proto proto;
	int (*connect)(struct camd *c);
	void (*disconnect)(struct camd *c);
	int (*reconnect)(struct camd *c);
	int (*do_emm)(struct camd *c, uint16_t ca_id, uint16_t service_id, uint8_t *data, uint8_t data_len);
	int (*do_ecm)(struct camd *c, uint16_t ca_id, uint16_t service_id, uint8_t *data, uint8_t data_len);
	int (*get_cw)(struct camd *c, uint16_t *ca_id, uint16_t *idx, uint8_t *cw);
};

struct cs378x {
	// cs378x private data
	uint8_t			buf[CAMD35_BUF_LEN];
	AES_KEY			aes_encrypt_key;
	AES_KEY			aes_decrypt_key;
	uint32_t		auth_token;
	uint16_t		msg_id;
};

struct camd {
	int				server_fd;
	struct in_addr	server_addr;
	unsigned int	server_port;
	char			user[64];
	char			pass[64];

	unsigned int	ecm_recv_errors; // Error counter, reset on successful send/recv
	unsigned int	emm_recv_errors; // Error counter, reset on successful send/recv

	struct key		*key;

	pthread_t		thread;
	QUEUE			*req_queue;
	QUEUE			*ecm_queue;
	QUEUE			*emm_queue;

	struct camd_ops	ops;
	struct cs378x	cs378x;
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
	struct ts_pat		*genpat;
	uint8_t				genpat_cc;
	struct ts_cat		*cat, *curcat;
	struct ts_pmt		*pmt, *curpmt;
	struct ts_sdt		*sdt, *cursdt;
	struct ts_privsec	*emm, *last_emm;
	struct ts_privsec	*ecm, *last_ecm;
	struct ts_privsec	*tmp_emm;
	struct ts_privsec	*tmp_ecm;
	uint16_t			pmt_pid;
	uint16_t			service_id;
	uint16_t			forced_service_id;
	uint16_t			emm_caid, emm_pid;
	uint16_t			ecm_caid, ecm_pid;
	uint16_t			forced_caid;
	uint16_t			forced_emm_pid;
	uint16_t			forced_ecm_pid;
	pidmap_t			pidmap;
	pidmap_t			cc; // Continuity counters
	pidmap_t			pid_seen;

	// Stats
	unsigned int		emm_seen_count;
	unsigned int		emm_processed_count;
	unsigned int		emm_report_interval;
	time_t				emm_last_report;

	unsigned int		ecm_seen_count;
	unsigned int		ecm_processed_count;
	unsigned int		ecm_duplicate_count;
	unsigned int		ecm_report_interval;
	time_t				ecm_last_report;

	unsigned int		cw_warn_sec;
	time_t				cw_last_warn;

	// CAMD handling
	struct key			key;
	struct camd			camd;

	// Config
	char				ident[128];
	char				syslog_host[128];
	int					syslog_port;
	int					syslog_active;
	int					syslog_remote;

	int					daemonize;
	char				pidfile[PATH_MAX];

	enum CA_system		req_CA_sys;

	int					emm_send;
	int					emm_only;
	int					pid_filter;
	int					eit_passthrough;
	int					tdt_passthrough;
	int					nit_passthrough;

	uint8_t				irdeto_ecm;
	int					ecm_cw_log;

	int					rtp_input;

	struct io			input;
	struct io			output;

	int					debug_level;
	int					ts_discont;

	int					camd_stop;
	int					is_cw_error;

	int					threaded;

	int					decode_stop;
	pthread_t			decode_thread;
	CBUF				*decode_buf;

	int					write_stop;
	pthread_t			write_thread;
	CBUF				*write_buf;

	struct notify		*notify;
	char				notify_program[512];
};

void data_init(struct ts *ts);
void data_free(struct ts *ts);

#endif
