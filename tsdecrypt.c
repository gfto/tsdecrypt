/*
 * tsdecrypt
 * Copyright (C) 2011-2012 Unix Solutions Ltd.
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
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <sys/resource.h>

#include <openssl/rand.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "csa.h"
#include "camd.h"
#include "process.h"
#include "udp.h"
#include "notify.h"
#include "filter.h"

#define FIRST_REPORT_SEC 3

#define PROGRAM_NAME "tsdecrypt"
static const char *program_id = PROGRAM_NAME " v" VERSION " (" GIT_VER ", build " BUILD_ID " " DLIB ")";

static int keep_running = 1;
static FILE *log_file = NULL;
static char *log_filename = NULL;
static int local_syslog = 0;
static int remote_syslog = 0;

static int packet_from_file = 0;
static int packet_buflen;
static uint8_t packet_buf[256];
static enum msg_type packet_type = ECM_MSG;

extern int ai_family;

static void do_log(FILE *f, time_t now, const char *msg) {
	char date[64];
	struct tm tm;
	// There is no need to show timestamps when debug options are used
	if (packet_from_file) {
		fprintf(f, "%s", msg);
		return;
	}
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime_r(&now, &tm));
	fprintf(f, "%s | %s", date, msg);
}

static void LOG_func(const char *msg) {
	time_t now = time(NULL);
	do_log(stderr, now, msg);
	if (log_file)
		do_log(log_file, now, msg);
	if (local_syslog)
		syslog(LOG_INFO, msg, strlen(msg));
	if (remote_syslog)
		LOG(msg);
}

static const char short_options[] = "i:d:N:Sl:L:F:I:RzM:T:W:O:o:t:rk:g:upwxyc:C:Y:Q:A:s:U:P:B:46eZ:Ef:a:X:vqH:G:KJ:D:jbhVn:m:";

// Unused short options: a01235789
static const struct option long_options[] = {
	{ "ident",				required_argument, NULL, 'i' },
	{ "daemon",				required_argument, NULL, 'd' },
	{ "syslog",				no_argument,       NULL, 'S' },
	{ "syslog-host",		required_argument, NULL, 'l' },
	{ "syslog-port",		required_argument, NULL, 'L' },
	{ "log-file",			required_argument, NULL, 'F' },
	{ "notify-program",		required_argument, NULL, 'N' },

	{ "input",				required_argument, NULL, 'I' },
	{ "input-rtp",			no_argument,       NULL, 'R' },
	{ "input-ignore-disc",	no_argument,       NULL, 'z' },
	{ "input-service",		required_argument, NULL, 'M' },
	{ "input-buffer",		required_argument, NULL, 'T' },
	{ "input-dump",			required_argument, NULL, 'W' },

	{ "output",				required_argument, NULL, 'O' },
	{ "output-intf",		required_argument, NULL, 'o' },
	{ "output-ttl",			required_argument, NULL, 't' },
	{ "output-rtp",			no_argument,       NULL, 'r' },
	{ "output-rtp-ssrc",	required_argument, NULL, 'k' },
	{ "output-tos",			required_argument, NULL, 'g' },
	{ "no-output-on-error",	no_argument,       NULL, 'u' },
	{ "no-output-filter",	no_argument,       NULL, 'p' },
	{ "output-nit-pass",	no_argument,       NULL, 'y' },
	{ "output-eit-pass",	no_argument,       NULL, 'w' },
	{ "output-tdt-pass",	no_argument,       NULL, 'x' },

	{ "ca-system",			required_argument, NULL, 'c' },
	{ "caid",				required_argument, NULL, 'C' },
	{ "const-cw",			required_argument, NULL, 'Y' },
	{ "biss-key",			required_argument, NULL, 'Q' },

	{ "camd-proto",			required_argument, NULL, 'A' },
	{ "camd-server",		required_argument, NULL, 's' },
	{ "camd-user",			required_argument, NULL, 'U' },
	{ "camd-pass",			required_argument, NULL, 'P' },
	{ "camd-des-key",		required_argument, NULL, 'B' },
	{ "ipv4",				no_argument,       NULL, '4' },
	{ "ipv6",				no_argument,       NULL, '6' },

	{ "emm",				no_argument,       NULL, 'e' },
	{ "emm-pid",			required_argument, NULL, 'Z' },
	{ "emm-only",			no_argument,       NULL, 'E' },
	{ "emm-report-time",	required_argument, NULL, 'f' },
	{ "emm-filter",			required_argument, NULL, 'a' },

	{ "ecm-pid",			required_argument, NULL, 'X' },
	{ "ecm-only",			no_argument,       NULL, 'v' },
	{ "ecm-report-time",	required_argument, NULL, 'H' },
	{ "ecm-irdeto-type",	required_argument, NULL, 'G' },
	{ "ecm-no-log",			no_argument      , NULL, 'K' },
	{ "cw-warn-time",		required_argument, NULL, 'J' },

	{ "ecm-and-emm-only",	no_argument,       NULL, 'q' },

	{ "debug",				required_argument, NULL, 'D' },
	{ "pid-report",			no_argument,       NULL, 'j' },
	{ "bench",				no_argument,       NULL, 'b' },
	{ "help",				no_argument,       NULL, 'h' },
	{ "version",			no_argument,       NULL, 'V' },

	{ "ecm-file",			required_argument, NULL, 'n' },
	{ "emm-file",			required_argument, NULL, 'm' },

	{ 0, 0, 0, 0 }
};

static void show_help(struct ts *ts) {
	printf("%s\n", program_id);
	printf("Copyright (C) 2011-2012 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: " PROGRAM_NAME " [opts]\n");
	printf("\n");
	printf("Main options:\n");
	printf(" -i --ident <server>        | Format PROVIDER/CHANNEL. Default: empty\n");
	printf(" -d --daemon <pidfile>      | Daemonize program and write pid file.\n");
	printf(" -N --notify-program <prg>  | Execute <prg> to report events. Default: empty\n");
	printf("\n");
	printf("Input options:\n");
	printf(" -I --input <source>        | Where to read from. File or multicast address.\n");
	printf("                            .    -I 224.0.0.1:5000    (v4 multicast)\n");
	printf("                            .    -I [ff01::1111]:5000 (v6 multicast)\n");
	printf("                            .    -I file://in.ts      (read from file)\n");
	printf("                            . By default the input is stdin.\n");
	printf(" -R --input-rtp             | Enable RTP input\n");
	printf(" -z --input-ignore-disc     | Do not report discontinuty errors in input.\n");
	printf(" -M --input-service <srvid> | Choose service id when input is MPTS.\n");
	printf(" -T --input-buffer <ms>     | Set input buffer time in ms. Default: %u\n", ts->input_buffer_time);
	printf(" -W --input-dump <filename> | Save input stream in file.\n");
	printf("\n");
	printf("Output options:\n");
	printf(" -O --output <dest>         | Where to send output. File or multicast address.\n");
	printf("                            .    -O 239.0.0.1:5000    (v4 multicast)\n");
	printf("                            .    -O [ff01::2222]:5000 (v6 multicast)\n");
	printf("                            .    -O file://out.ts     (write to file)\n");
	printf("                            . By default the output is stdout.\n");
	printf(" -o --output-intf <value>   | Set multicast output interface.\n");
	printf("                            . Default for IPv4: 0.0.0.0 (intf addr)\n");
	printf("                            . Default for IPv6: -1      (intf number)\n");
	printf(" -t --output-ttl <ttl>      | Set multicast ttl. Default: %d\n", ts->output.ttl);
	printf(" -r --output-rtp            | Enable RTP output.\n");
	printf(" -k --output-rtp-ssrc <id>  | Set RTP SSRC. Default: %u\n", ts->rtp_ssrc);
	printf(" -g --output-tos <tos>      | Set TOS value of output packets. Default: none\n");
	printf(" -u --no-output-on-error    | Do not output data when the code word is missing.\n");
	printf(" -p --no-output-filter      | Disable output filtering. Default: %s\n", ts->pid_filter ? "enabled" : "disabled");
	printf(" -y --output-nit-pass       | Pass through NIT.\n");
	printf(" -w --output-eit-pass       | Pass through EIT (EPG).\n");
	printf(" -x --output-tdt-pass       | Pass through TDT/TOT.\n");
	printf("\n");
	printf("CA options:\n");
	printf(" -c --ca-system <ca_sys>    | Process input EMM/ECM from <ca_sys>.\n");
	printf("                            | Valid systems are: CONAX (default), CRYPTOWORKS,\n");
	printf("                            .   IRDETO, SECA (MEDIAGUARD), VIACCESS,\n");
	printf("                            .   VIDEOGUARD (NDS), NAGRA, DRECRYPT, BULCRYPT,\n");
	printf("                            .   GRIFFIN and DGCRYPT.\n");
	printf(" -C --caid <caid>           | Set CAID. Default: Taken from --ca-system.\n");
	printf(" -Y --const-cw <codeword>   | Set constant code word for decryption.\n");
	printf("                            . Example cw: a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8\n");
	printf(" -Q --biss-key <biss-key>   | Set BISS key for decryption.\n");
	printf("                            . Example key: 112233445566\n");
	printf("\n");
	printf("CAMD server options:\n");
	printf(" -A --camd-proto <proto>    | Set CAMD network protocol.\n");
	printf("                            . Valid protocols are: CS378X (default) and NEWCAMD\n");
	printf(" -s --camd-server <host>    | Set CAMD server address. Default port: 2233\n");
	printf("                            . Example IPv4 addr and port: 127.0.0.1:2233\n");
	printf("                            . Example IPv6 addr and port: [2a00::1014]:2233\n");
	printf("                            . Example hostname          : example.com\n");
	printf("                            . Example hostname and port : example.com:2233\n");
	printf("                            . Example IPv4 hostname     : ipv4.google.com\n");
	printf("                            . Example IPv6 hostname     : ipv6.google.com\n");
	printf(" -U --camd-user <user>      | Set CAMD server user. Default: %s\n", ts->camd.user);
	printf(" -P --camd-pass <pass>      | Set CAMD server password. Default: %s\n", ts->camd.pass);
	printf(" -B --camd-des-key <key>    | Set DES key for newcamd protocol.\n");
	printf("                            . Default: %s\n", ts->camd.newcamd.hex_des_key);
	printf(" -4 --ipv4                  | Use only IPv4 addresses of the camd server.\n");
	printf(" -6 --ipv6                  | Use only IPv6 addresses of the camd server.\n");
	printf("\n");
	printf("EMM options:\n");
	printf(" -e --emm                   | Enable sending EMM's to CAMD. Default: %s\n", ts->process_emm ? "enabled" : "disabled");
	printf(" -E --emm-only              | Send only EMMs to CAMD, skipping ECMs and without\n");
	printf("                            .   decoding the input stream.\n");
	printf(" -Z --emm-pid <pid>         | Force EMM pid. Default: none\n");
	printf(" -f --emm-report-time <sec> | Report each <sec> seconds how much EMMs have been\n");
	printf("                            .   received/processed. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->emm_report_interval);
	printf(" -a --emm-filter <filter>   | Add EMM filter defined by <filter>.\n");
	printf("                            . This option can be used multiple times (max:%u).\n", MAX_FILTERS);
	printf("                            . See FILTERING file for more info.\n");
	printf("\n");
	printf("ECM options:\n");
	printf(" -X --ecm-pid <pid>         | Force ECM pid. Default: none\n");
	printf(" -v --ecm-only              | Send only ECMs to CAMD, skipping EMMs and without\n");
	printf("                            .   decoding the input stream.\n");
	printf(" -H --ecm-report-time <sec> | Report each <sec> how much ECMs and CWs have been\n");
	printf("                            .   processed/skipped. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->ecm_report_interval);
	printf(" -G --ecm-irdeto-type <int> | Process IRDETO ECMs with type X /0-3/. Default: %d\n", ts->irdeto_ecm);
	printf(" -K --ecm-no-log            | Disable ECM and code words logging.\n");
	printf(" -J --cw-warn-time <sec>    | Warn if no valid code word has been received.\n");
	printf("                            .   Set <sec> to 0 to disable. Default: %d sec\n", ts->cw_warn_sec);
	printf("\n");
	printf(" -q --ecm-and-emm-only      | Send ECMs and EMMs to CAMD but do not decode\n");
	printf("                            .   the input stream.\n");
	printf("\n");
	printf("Logging options:\n");
	printf(" -S --syslog                | Log messages using syslog.\n");
	printf(" -l --syslog-host <host>    | Syslog server address. Default: disabled\n");
	printf(" -L --syslog-port <port>    | Syslog server port. Default: %d\n", ts->syslog_port);
	printf(" -F --log-file <filename>   | Log to file <filename>.\n");
	printf(" -D --debug <level>         | Message debug level.\n");
	printf("                            .    0 = default messages\n");
	printf("                            .    1 = show PSI tables\n");
	printf("                            .    2 = show EMMs\n");
	printf("                            .    3 = show duplicate ECMs\n");
	printf("                            .    4 = packet debug\n");
	printf("                            .    5 = packet debug + packet dump\n");
	printf("\n");
	printf("Debugging options:\n");
	printf(" -n --ecm-file <file.txt>   | Read ECM from text file.\n");
	printf(" -m --emm-file <file.txt>   | Read EMM from text file.\n");
	printf("\n");
	printf("Misc options:\n");
	printf(" -j --pid-report            | Report how much packets were received.\n");
	printf(" -b --bench                 | Benchmark decrypton.\n");
	printf(" -h --help                  | Show help screen.\n");
	printf(" -V --version               | Show program version.\n");
	printf("\n");
}

static int parse_io_param(struct io *io, char *opt, int open_flags, mode_t open_mode) {
	int port_set = 0, host_set;
	io->type = WTF_IO;
	if (strstr(opt, "file://") == opt) {
		io->fname = opt + 7; // strlen("file://")
		io->type = FILE_IO;
	} else if (strchr(opt, '/')) {
		io->fname = opt;
		io->type = FILE_IO;
	}
	if (io->type == FILE_IO) {
		io->fd = open(io->fname, open_flags, open_mode);
		if (io->fd < 0) {
			fprintf(stderr, "ERROR: Can not open file (%s): %s\n", io->fname, strerror(errno));
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	io->type = NET_IO;
	host_set = parse_host_and_port(opt, &io->hostname, &io->service, &port_set);
	return !(!port_set || !host_set);
}

extern char *optarg;
extern int optind, opterr, optopt;

static void parse_options(struct ts *ts, int argc, char **argv) {
	int j, i, ca_err = 0, server_err = 1, input_addr_err = 0, output_addr_err = 0, ident_err = 0, port_set = 0;
	opterr = 0; // Prevent printing of error messages for unknown options in getopt()
	while ((j = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
		if (j == '?') {
			fprintf(stderr, "ERROR: Unknown parameter '%s'.\n", argv[optind - 1]);
			exit(EXIT_FAILURE);
		}
		switch (j) {
			case 'i': // -- ident
				ts->ident = optarg;
				break;
			case 'd': // --daemon
				ts->pidfile = optarg;
				break;
			case 'N': // --notify-program
				ts->notify_program = optarg;
				break;

			case 'S': // --syslog
				ts->syslog_active = 1;
				ts->syslog_remote = 0;
				break;
			case 'l': // --syslog-host
				ts->syslog_host = optarg;
				ts->syslog_active = 1;
				ts->syslog_remote = 1;
				break;
			case 'L': // --syslog-port
				ts->syslog_port = atoi(optarg);
				break;
			case 'F': // --log-file
				log_filename = optarg;
				break;

			case 'I': // --input
				input_addr_err = !parse_io_param(&ts->input, optarg, O_RDONLY, 0);
				break;
			case 'R': // --input-rtp
				ts->rtp_input = !ts->rtp_input;
				break;
			case 'z': // --input-ignore-disc
				ts->ts_discont = !ts->ts_discont;
				break;
			case 'M': // --input-service
				ts->forced_service_id = strtoul(optarg, NULL, 0) & 0xffff;
				break;
			case 'T': // --input-buffer
				ts->input_buffer_time = strtoul(optarg, NULL, 0);
				break;
			case 'W': // --input-dump
				ts->input_dump_filename = optarg;
				break;

			case 'O': // --output
				output_addr_err = !parse_io_param(&ts->output, optarg,
					O_CREAT | O_WRONLY | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				break;
			case 'o': // --output-intf
				if (strchr(optarg, '.'))
					inet_aton(optarg, &ts->output.intf);
				else
					ts->output.v6_if_index = atoi(optarg);
				break;
			case 't': // --output-ttl
				ts->output.ttl = atoi(optarg);
				break;
			case 'r': // --output-rtp
				ts->rtp_output = 1;
				break;
			case 'k': // --output-rtp-ssrc
				ts->rtp_ssrc = strtoul(optarg, NULL, 0);
				break;
			case 'g': // --output-tos
				ts->output.tos = (uint8_t)strtol(optarg, NULL, 0);
				break;
			case 'u': // --no-output-on-error
				ts->no_output_on_error = !ts->no_output_on_error;
				break;
			case 'p': // --no-output-filter
				ts->pid_filter = !ts->pid_filter;
				break;
			case 'y': // --output-nit-pass
				ts->nit_passthrough = !ts->nit_passthrough;
				break;
			case 'w': // --output-eit-pass
				ts->eit_passthrough = !ts->eit_passthrough;
				break;
			case 'x': // --output-tdt-pass
				ts->tdt_passthrough = !ts->tdt_passthrough;
				break;
			case 'c': // --ca-system
				if (strcasecmp("IRDETO", optarg) == 0)
					ts->req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0 || strcasecmp("CONAX", optarg) == 0)
					ts->req_CA_sys = CA_CONAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					ts->req_CA_sys = CA_CRYPTOWORKS;
				else if (strcasecmp("SECA", optarg) == 0 || strcasecmp("MEDIAGUARD", optarg) == 0)
					ts->req_CA_sys = CA_SECA;
				else if (strcasecmp("VIACCESS", optarg) == 0)
					ts->req_CA_sys = CA_VIACCESS;
				else if (strcasecmp("VIDEOGUARD", optarg) == 0 || strcasecmp("NDS", optarg) == 0)
					ts->req_CA_sys = CA_VIDEOGUARD;
				else if (strcasecmp("NAGRA", optarg) == 0)
					ts->req_CA_sys = CA_NAGRA;
				else if (strcasecmp("DRE-CRYPT", optarg) == 0 || strcasecmp("DRECRYPT", optarg) == 0)
					ts->req_CA_sys = CA_DRECRYPT;
				else if (strcasecmp("BULCRYPT", optarg) == 0)
					ts->req_CA_sys = CA_BULCRYPT;
				else if (strcasecmp("GRIFFIN", optarg) == 0)
					ts->req_CA_sys = CA_GRIFFIN;
				else if (strcasecmp("DGCRYPT", optarg) == 0)
					ts->req_CA_sys = CA_DGCRYPT;
				else
					ca_err = 1;
				break;
			case 'C': // --caid
				ts->forced_caid = strtoul(optarg, NULL, 0) & 0xffff;
				break;
			case 'Y': // --const-cw
				ts->camd.constant_codeword = 1;
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				if (strlen(optarg) != CODEWORD_LENGTH * 2) {
					fprintf(stderr, "ERROR: Constant code word should be %u characters long.\n", CODEWORD_LENGTH * 2);
					exit(EXIT_FAILURE);
				}
				if (decode_hex_string(optarg, ts->camd.key->cw, strlen(optarg)) < 0) {
					fprintf(stderr, "ERROR: Invalid hex string for constant code word: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				camd_set_cw(ts, ts->camd.key->cw, 0);
				ts->camd.key->is_valid_cw = 1;
				break;
			case 'Q': // --biss-key
				ts->camd.constant_codeword = 1;
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				uint8_t *key = ts->camd.key->cw;
				// Sometimes the BISS keys are entered with their checksums already calculated (16 symbols, 8 bytes)
				// This is the same as constant cw with the same key for even and odd
				if (strlen(optarg) == (BISSKEY_LENGTH + 2) * 2) {
					if (decode_hex_string(optarg, key, strlen(optarg)) < 0) {
						fprintf(stderr, "ERROR: Invalid hex string for BISS key: %s\n", optarg);
						exit(EXIT_FAILURE);
					}
				} else {
					// BISS key without checksum (12 symbols, 6 bytes)
					if (strlen(optarg) != BISSKEY_LENGTH * 2) {
						fprintf(stderr, "ERROR: BISS key should be %u characters long.\n", BISSKEY_LENGTH * 2);
						exit(EXIT_FAILURE);
					}
					if (decode_hex_string(optarg, key, strlen(optarg)) < 0) {
						fprintf(stderr, "ERROR: Invalid hex string for BISS key: %s\n", optarg);
						exit(EXIT_FAILURE);
					}
					// Calculate BISS KEY crc
					memmove(key + 4, key + 3, 3);
					key[3] = (uint8_t)(key[0] + key[1] + key[2]);
					key[7] = (uint8_t)(key[4] + key[5] + key[6]);
				}
				// Even and odd keys are the same
				memcpy(key + 8, key, 8);
				camd_set_cw(ts, ts->camd.key->cw, 0);
				ts->camd.key->is_valid_cw = 1;
				break;

			case 'A': // --camd-proto
				if (strcasecmp(optarg, "cs378x") == 0) {
					camd_proto_cs378x(&ts->camd.ops);
				} else if (strcasecmp(optarg, "newcamd") == 0) {
					camd_proto_newcamd(&ts->camd.ops);
				} else {
					fprintf(stderr, "Unknown CAMD protocol: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 's': // --camd-server
				server_err = !parse_host_and_port(optarg, &ts->camd.hostname, &ts->camd.service, &port_set);
				break;
			case 'U': // --camd-user
				if (strlen(optarg) < 64)
					ts->camd.user = optarg;
				break;
			case 'P': // --camd-pass
				ts->camd.pass = optarg;
				break;
			case 'B': // --camd-des-key
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				if (strlen(optarg) != DESKEY_LENGTH) {
					fprintf(stderr, "ERROR: des key should be %u characters long.\n", DESKEY_LENGTH);
					exit(EXIT_FAILURE);
				}
				strncpy(ts->camd.newcamd.hex_des_key, optarg, sizeof(ts->camd.newcamd.hex_des_key) - 1);
				ts->camd.newcamd.hex_des_key[sizeof(ts->camd.newcamd.hex_des_key) - 1] = 0;
				break;
			case '4': // --ipv4
				ai_family = AF_INET;
				break;
			case '6': // --ipv6
				ai_family = AF_INET6;
				break;

			case 'e': // --emm
				ts->process_emm = !ts->process_emm;
				break;
			case 'Z': // --emm-pid
				ts->forced_emm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'E': // --emm-only
				ts->process_emm = 1;
				ts->process_ecm = 0;
				ts->output_stream = 0;
				break;
			case 'f': // --emm-report-time
				ts->emm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->emm_report_interval > 86400)
					ts->emm_report_interval = 86400;
				break;

			case 'a': // --emm-filter
				if (ts->emm_filters_num + 1 > MAX_FILTERS) {
					fprintf(stderr, "ERROR: Maximum allowed filters are %d.\n", MAX_FILTERS);
					exit(EXIT_FAILURE);
				}
				if (filter_parse(optarg, &ts->emm_filters[ts->emm_filters_num])) {
					ts->emm_filters_num++;
				} else {
					fprintf(stderr, "ERROR: Can't parse EMM filter: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;

			case 'X': // --ecm-pid
				ts->forced_ecm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'v': // --ecm-only
				ts->process_emm = 0;
				ts->process_ecm = 1;
				ts->output_stream = 0;
				break;
			case 'H': // --ecm-report-time
				ts->ecm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->ecm_report_interval > 86400)
					ts->ecm_report_interval = 86400;
				break;
			case 'G': // --ecm-irdeto-type
				ts->irdeto_ecm = atoi(optarg);
				break;
			case 'K': // --ecm-no-log
				ts->ecm_cw_log = !ts->ecm_cw_log;
				break;
			case 'J': // --cw-warn-time
				ts->cw_warn_sec = strtoul(optarg, NULL, 10);
				if (ts->cw_warn_sec > 86400)
					ts->cw_warn_sec = 86400;
				ts->cw_last_warn= ts->cw_last_warn + ts->cw_warn_sec;
				break;
			case 'q': // --ecm-and-emm-only
				ts->process_emm = 1;
				ts->process_ecm = 1;
				ts->output_stream = 0;
				break;

			case 'D': // --debug
				ts->debug_level = atoi(optarg);
				if (ts->debug_level > 0)
					ts->pid_report = 1;
				break;
			case 'j': // --pid-report
				ts->pid_report = 1;
				break;
			case 'b': // --bench
				csa_benchmark();
				exit(EXIT_SUCCESS);

			case 'n': // --ecm-file
			case 'm': // --emm-file
				packet_from_file = 1;
				packet_buflen = file_hex2buf(optarg, packet_buf, sizeof(packet_buf));
				if (!packet_buflen) {
					fprintf(stderr, "ERROR: Can't init packet from file.\n");
					exit(1);
				}
				packet_type = j == 'n' ? ECM_MSG : EMM_MSG;
				break;

			case 'h': // --help
				show_help(ts);
				exit(EXIT_SUCCESS);

			case 'V': // --version
				printf("%s\n", program_id);
				exit(EXIT_SUCCESS);
		}
	}
	if (!ts->ident) {
		if (ts->syslog_active || ts->notify_program)
			ident_err = 1;
	}

	if (packet_from_file) {
		int err = 0;
		if (!ts->forced_caid) {
			fprintf(stderr, "ERROR: CAID was not set. Use --caid option.\n");
			err++;
		}
		if (!ts->forced_service_id) {
			fprintf(stderr, "ERROR: Service id was not set. Use --input-service option.\n");
			err++;
		}
		if (err)
			exit(EXIT_FAILURE);

		ts->threaded = 0;
		input_addr_err = 0;
		output_addr_err = 0;
		ts->input.type = FILE_IO;
		ts->input.fd = 0;
		ts->output.type = FILE_IO;
		ts->output.fd = 1;
		ts->pid_filter = 0;
		ts->process_ecm = 0;
		ts->process_emm = 0;
		ts->output_stream = 0;
		ts->camd.no_reconnect = 1;
		ts->camd.check_emm_errors = 1;
		ts->emm_filters_num = 0;
	}

	// Constant codeword is special. Disable conflicting options
	if (ts->camd.constant_codeword) {
		server_err = 0; // No server settings are required
		ts->process_ecm = 0;
		ts->process_emm = 0;
		ts->output_stream = 1;
	}

	if (ident_err || ca_err || server_err || input_addr_err || output_addr_err || ts->input.type == WTF_IO || ts->output.type == WTF_IO) {
		show_help(ts);
		if (ident_err)
			fprintf(stderr, "ERROR: Ident is not set, please use --ident option.\n");
		if (ca_err)
			fprintf(stderr, "ERROR: Requested CA system is unsupported.\n");
		if (server_err)
			fprintf(stderr, "ERROR: CAMD server address is not set or it is invalid.\n");
		if (input_addr_err)
			fprintf(stderr, "ERROR: Input address is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output address is invalid.\n");
		exit(EXIT_FAILURE);
	}
	if (decode_hex_string(ts->camd.newcamd.hex_des_key, ts->camd.newcamd.bin_des_key, DESKEY_LENGTH) < 0) {
		fprintf(stderr, "ERROR: Invalid hex string for des key: %s\n", ts->camd.newcamd.hex_des_key);
		exit(EXIT_FAILURE);
	}
	if (ts->camd.ops.proto == CAMD_NEWCAMD && !port_set) {
		fprintf(stderr, "ERROR: CAMD server port is not set. Use --camd-server %s:xxxx to set the port.\n", ts->camd.hostname);
		exit(EXIT_FAILURE);
	}

	if (log_filename) {
		log_file = fopen(log_filename, "a");
		if (!log_file) {
			fprintf(stderr, "ERROR: Can't open log file %s: %s\n", log_filename, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (ts->ident)
		ts_LOGf("Ident      : %s\n", ts->ident);
	if (ts->notify_program)
		ts_LOGf("Notify prg : %s\n", ts->notify_program);
	if (ts->pidfile)
		ts_LOGf("Daemonize  : %s pid file.\n", ts->pidfile);
	if (ts->syslog_active) {
		if (ts->syslog_remote)
			ts_LOGf("Syslog     : %s:%d\n", ts->syslog_host, ts->syslog_port);
		else
			ts_LOGf("Syslog     : enabled\n");
	} else {
		if (!packet_from_file)
			ts_LOGf("Syslog     : disabled\n");
	}

	if (!ts->camd.constant_codeword) {
		if (ts->forced_caid)
			ts->req_CA_sys = ts_get_CA_sys(ts->forced_caid);
		if (!ts->forced_caid)
			ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
		else
			ts_LOGf("CA System  : %s | CAID: 0x%04x (%d)\n",
				ts_get_CA_sys_txt(ts->req_CA_sys),
				ts->forced_caid, ts->forced_caid);
	} else {
		char cw_even[64], cw_odd[64];
		ts_hex_dump_buf(cw_even, sizeof(cw_even), ts->key.cw    , 8, 0);
		ts_hex_dump_buf(cw_odd , sizeof(cw_odd ), ts->key.cw + 8, 8, 0);
		ts_LOGf("Constant CW: even = %s\n", cw_even);
		ts_LOGf("Constant CW: odd  = %s\n", cw_odd);
	}

	if (ts->input.type == NET_IO) {
		ts_LOGf("Input addr : %s://%s:%s/\n",
			ts->rtp_input ? "rtp" : "udp",
			ts->input.hostname, ts->input.service);
		if (ts->input_buffer_time) {
			ts_LOGf("Input buff : %u ms\n", ts->input_buffer_time);
		}
	} else if (ts->input.type == FILE_IO) {
		if (!packet_from_file)
			ts_LOGf("Input file : %s\n", ts->input.fd == 0 ? "STDIN" : ts->input.fname);
	}
	if (ts->input_dump_filename) {
		ts->input_dump_file = fopen(ts->input_dump_filename, "w");
		if (ts->input_dump_file)
			ts_LOGf("Input dump : %s\n", ts->input_dump_filename);
		else
			ts_LOGf("Input dump : %s | ERROR: %s\n", ts->input_dump_filename, strerror(errno));
	}
	if (ts->forced_service_id)
		ts_LOGf("Service id : 0x%04x (%d)\n",
			ts->forced_service_id, ts->forced_service_id);
	if (ts->req_CA_sys == CA_IRDETO)
		ts_LOGf("Irdeto ECM : %d\n", ts->irdeto_ecm);

	if (ts->output_stream) {
		if (ts->output.type == NET_IO) {
			ts_LOGf("Output addr: %s://%s:%s/\n",
				ts->rtp_output ? "rtp" : "udp",
				ts->output.hostname, ts->output.service);
			ts_LOGf("Output intf: %s (IPv6 intf index:%d)\n",
				inet_ntoa(ts->output.intf), ts->output.v6_if_index);
			ts_LOGf("Output ttl : %d\n", ts->output.ttl);
			if (ts->output.tos > -1)
				ts_LOGf("Output TOS : %u (0x%02x)\n", ts->output.tos, ts->output.tos);
			if (ts->rtp_output) {
				ts_LOGf("RTP SSRC   : %u (0x%04x)\n",
					ts->rtp_ssrc, ts->rtp_ssrc);
				// It is recommended that RTP seqnum starts with random number
				RAND_bytes((unsigned char *)&(ts->rtp_seqnum), 2);
			}
		} else if (ts->output.type == FILE_IO) {
			ts_LOGf("Output file: %s\n", ts->output.fd == 1 ? "STDOUT" : ts->output.fname);
		}
		ts_LOGf("Out filter : %s (%s)%s\n",
			ts->pid_filter ? "enabled" : "disabled",
			ts->pid_filter ? "output only service related PIDs" : "output everything",
			ts->no_output_on_error ? " (No output on CW error)" : ""
		);
		if (ts->pid_filter) {
			if (ts->nit_passthrough)
				ts_LOGf("Out filter : Pass through NIT.\n");
			if (ts->eit_passthrough)
				ts_LOGf("Out filter : Pass through EIT (EPG).\n");
			if (ts->tdt_passthrough)
				ts_LOGf("Out filter : Pass through TDT/TOT.\n");
		}
		ts_LOGf("TS discont : %s\n", ts->ts_discont ? "report" : "ignore");
		ts->threaded = !(ts->input.type == FILE_IO && ts->input.fd != 0);
		ts_LOGf("Decoding   : %s\n", ts->threaded ? "threaded" : "single thread");
	} else {
		ts_LOGf("Decoding   : disabled\n");
	}

	if (!ts->camd.constant_codeword) {
		ts_LOGf("CAMD proto : %s\n", ts->camd.ops.ident);
		ts_LOGf("CAMD addr  : %s:%s%s\n", ts->camd.hostname, ts->camd.service,
			ai_family == AF_INET  ? " (IPv4 only)" :
			ai_family == AF_INET6 ? " (IPv6 only)" :
			" (IPv4/IPv6)"
		);
		ts_LOGf("CAMD user  : %s\n", ts->camd.user);
		ts_LOGf("CAMD pass  : %s\n", ts->camd.pass);
		if (ts->camd.ops.proto == CAMD_NEWCAMD)
			ts_LOGf("CAMD deskey: %s\n", ts->camd.newcamd.hex_des_key);
	}

	if (!packet_from_file)
		ts_LOGf("EMM process: %s\n", ts->process_emm ? "Yes" : "No");

	if (ts->process_emm) {
		if (ts->forced_emm_pid)
			ts_LOGf("EMM pid    : 0x%04x (%d)\n", ts->forced_emm_pid, ts->forced_emm_pid);

		if (ts->emm_report_interval)
			ts_LOGf("EMM report : %d sec\n", ts->emm_report_interval);
		else
			ts_LOGf("EMM report : disabled\n");

		for (i = 0; i < ts->emm_filters_num; i++) {
			char tmp[512];
			filter_dump(&ts->emm_filters[i], tmp, sizeof(tmp));
			ts_LOGf("EMM filter : [%2d] %s\n", i + 1,  tmp);
		}
	}

	if (!packet_from_file)
		ts_LOGf("ECM process: %s\n", ts->process_ecm ? "Yes" : "No");

	if (ts->process_ecm) {
		if (ts->forced_ecm_pid)
			ts_LOGf("ECM pid    : 0x%04x (%d)\n", ts->forced_ecm_pid, ts->forced_ecm_pid);

		if (ts->ecm_report_interval)
			ts_LOGf("ECM report : %d sec\n", ts->emm_report_interval);
		else
			ts_LOGf("ECM report : disabled\n");

		if (ts->cw_warn_sec)
			ts_LOGf("CW warning : %d sec\n", ts->cw_warn_sec);
		else
			ts_LOGf("CW warning : disabled\n");

		if (!ts->ecm_cw_log)
			ts_LOGf("ECM/CW log : disabled\n");
	}

	if (ts->ident) {
		int len = strlen(ts->ident);
		for (i = 0; i < len; i++) {
			if (ts->ident[i] == '/')
				ts->ident[i] = '-';
		}
	}
}

static void report_emms(struct ts *ts, time_t now) {
	ts_LOGf("EMM | Received %u, Skipped %u, Sent %u, Processed %u in %lu seconds.\n",
		ts->emm_input_count,
		ts->emm_skipped_count,
		ts->emm_seen_count,
		ts->emm_processed_count,
		now - ts->emm_last_report);
	if (ts->emm_seen_count == 0) {
		notify(ts, "NO_EMM_RECEIVED", "No EMMs were received in last %lu seconds.",
			now - ts->emm_last_report);
	}
	ts->emm_last_report = now;
	ts->emm_input_count = 0;
	ts->emm_seen_count = 0;
	ts->emm_skipped_count = 0;
	ts->emm_processed_count = 0;
}

static void report_ecms(struct ts *ts, time_t now) {
	ts_LOGf("ECM | Received %u (%u dup) and processed %u in %lu seconds.\n",
		ts->ecm_seen_count,
		ts->ecm_duplicate_count,
		ts->ecm_processed_count,
		now - ts->ecm_last_report);
	ts->ecm_last_report = now;
	ts->ecm_seen_count = 0;
	ts->ecm_duplicate_count = 0;
	ts->ecm_processed_count = 0;
}

static void report_cw_warn(struct ts *ts, time_t now) {
	if (now - ts->key.ts > 1) {
		notify(ts, "NO_CODE_WORD", "No valid code word was received in %ld sec.",
			now - ts->key.ts);
		ts_LOGf("CW  | *ERR* No valid code word was received for %ld seconds!\n",
			now - ts->key.ts);
	}
	ts->cw_last_warn = now;
	ts->cw_next_warn = now + ts->cw_warn_sec;
}

static void do_reports(struct ts *ts) {
	static int first_emm_report = 1;
	static int first_ecm_report = 1;
	time_t now = time(NULL);
	if (ts->process_emm && ts->emm_report_interval) {
		if (first_emm_report && now >= ts->emm_last_report) {
			first_emm_report = 0;
			ts->emm_last_report -= FIRST_REPORT_SEC;
			report_emms(ts, now);
		} else if ((time_t)(ts->emm_last_report + ts->emm_report_interval) <= now) {
			report_emms(ts, now);
		}
	}
	if (ts->process_ecm && ts->ecm_report_interval) {
		if (first_ecm_report && now >= ts->ecm_last_report) {
			first_ecm_report = 0;
			ts->ecm_last_report -= FIRST_REPORT_SEC;
			report_ecms(ts, now);
		} else if ((time_t)(ts->ecm_last_report + ts->ecm_report_interval) <= now) {
			report_ecms(ts, now);
		}
	}

	if (ts->process_ecm && !ts->key.is_valid_cw) {
		if (ts->cw_warn_sec && now >= ts->cw_next_warn) {
			report_cw_warn(ts, now);
		}
	}
}

void signal_quit(int sig) {
	if (!keep_running)
		raise(sig);
	keep_running = 0;
	ts_LOGf("Killed %s with signal %d\n", program_id, sig);
	signal(sig, SIG_DFL);
}

#define RTP_HDR_SZ  12

static uint8_t ts_packet[FRAME_SIZE + RTP_HDR_SZ];
static uint8_t rtp_hdr[2][RTP_HDR_SZ];
static struct ts ts;

int main(int argc, char **argv) {
	ssize_t readen;
	int have_data = 1;
	int ntimeouts = 0;
	time_t timeout_start = time(NULL);
	int rtp_hdr_pos = 0, num_packets = 0;
	struct rlimit rl;

	if (getrlimit(RLIMIT_STACK, &rl) == 0) {
		if (rl.rlim_cur > THREAD_STACK_SIZE) {
			rl.rlim_cur = THREAD_STACK_SIZE;
			setrlimit(RLIMIT_STACK, &rl);
		}
	}

	memset(rtp_hdr[0], 0, RTP_HDR_SZ);
	memset(rtp_hdr[1], 0, RTP_HDR_SZ);

	data_init(&ts);

	ts_set_log_func(LOG_func);

	parse_options(&ts, argc, argv);

	if (ts.pidfile)
		daemonize(ts.pidfile);

	if (ts.syslog_active) {
		if (ts.syslog_remote) {
			log_init(ts.ident, 1, 1, ts.syslog_host, ts.syslog_port);
			remote_syslog = 1;
		} else {
			openlog(ts.ident, LOG_NDELAY | LOG_PID, LOG_USER);
			local_syslog = 1;
		}
	}

	ts.notify = notify_alloc(&ts);

	ts_LOGf("Start %s\n", program_id);
	notify(&ts, "START", "Starting %s", program_id);

	if (ts.input.type == NET_IO && udp_connect_input(&ts.input) < 1)
		goto EXIT;
	if (ts.output.type == NET_IO && udp_connect_output(&ts.output) < 1)
		goto EXIT;

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	signal(SIGINT , signal_quit);
	signal(SIGTERM, signal_quit);

	if (ts.threaded) {
		pthread_create(&ts.decode_thread, &ts.thread_attr, &decode_thread, &ts);
		pthread_create(&ts.write_thread , &ts.thread_attr, &write_thread , &ts);
	}

	ts.emm_last_report = time(NULL) + FIRST_REPORT_SEC;
	ts.ecm_last_report = time(NULL) + FIRST_REPORT_SEC;
	camd_start(&ts);

	if (packet_from_file) {
		uint8_t tmp[2048];
		ts_hex_dump_buf((char *)tmp, sizeof(tmp), packet_buf, packet_buflen, 16);
		ts_LOGf("%s | Processing packet with CAID 0x%04x\n", packet_type == ECM_MSG ? "ECM" : "EMM", ts.forced_caid);
		ts_LOGf("%s | Packet dump:\n%s\n", packet_type == ECM_MSG ? "ECM" : "EMM", tmp);
		camd_process_packet(&ts, camd_msg_alloc(packet_type, ts.forced_caid, ts.forced_service_id, packet_buf, packet_buflen));
		goto EXIT;
	}

	do {
		if (!ts.camd.constant_codeword)
			do_reports(&ts);

		if (ts.input.type == NET_IO) {
			set_log_io_errors(0);
			if (!ts.rtp_input) {
				readen = fdread_ex(ts.input.fd, (char *)ts_packet, FRAME_SIZE, 250, 4, 1);
			} else {
				readen = fdread_ex(ts.input.fd, (char *)ts_packet, FRAME_SIZE + RTP_HDR_SZ, 250, 4, 1);
				if (readen > RTP_HDR_SZ) {
					memcpy(rtp_hdr[rtp_hdr_pos], ts_packet, RTP_HDR_SZ);
					memmove(ts_packet, ts_packet + RTP_HDR_SZ, FRAME_SIZE);
					readen -= RTP_HDR_SZ;
					uint16_t ssrc  = (rtp_hdr[rtp_hdr_pos][2] << 8) | rtp_hdr[rtp_hdr_pos][3];
					uint16_t pssrc = (rtp_hdr[!rtp_hdr_pos][2] << 8) | rtp_hdr[!rtp_hdr_pos][3];
					rtp_hdr_pos = !rtp_hdr_pos;
					if (pssrc + 1 != ssrc && (ssrc != 0 && pssrc != 0xffff) && num_packets > 2)
						if (ts.ts_discont)
							ts_LOGf("--- | RTP discontinuity last_ssrc %5d, curr_ssrc %5d, lost %d packet\n",
								pssrc, ssrc, ((ssrc - pssrc)-1) & 0xffff);
					num_packets++;
				}
			}
			set_log_io_errors(1);
			if (readen < 0) {
				ts_LOGf("--- | Input read timeout.\n");
				if (!ntimeouts) {
					timeout_start = time(NULL);
					notify(&ts, "INPUT_TIMEOUT", "Read timeout on input %s://%s:%s/",
							ts.rtp_input ? "rtp" : "udp",
							ts.input.hostname, ts.input.service);
				}
				ntimeouts++;
			} else {
				if (ntimeouts && readen > 0) {
					notify(&ts, "INPUT_OK", "Data is available on input %s://%s:%s/ after %ld seconds timeout.",
							ts.rtp_input ? "rtp" : "udp",
							ts.input.hostname, ts.input.service,
							(time(NULL) - timeout_start) + 2); // Timeout is detected when ~2 seconds there is no incoming data
					ntimeouts = 0;
				}
			}
		} else {
			readen = read(ts.input.fd, ts_packet, FRAME_SIZE);
			have_data = !(readen <= 0);
		}
		if (readen > 0) {
			if (ts.input_dump_file)
				fwrite(ts_packet, readen, 1, ts.input_dump_file);
			process_packets(&ts, ts_packet, readen);
		}
		if (!keep_running)
			break;
	} while (have_data);
EXIT:
	camd_stop(&ts);

	if (ts.threaded) {
		ts.decode_stop = 1;
		ts.write_stop = 1;

		if (ts.decode_thread)
			pthread_join(ts.decode_thread, NULL);
		if (ts.write_thread)
			pthread_join(ts.write_thread, NULL);
	}

	show_pid_report(&ts);

	notify_sync(&ts, "STOP", "Stopping %s", program_id);
	ts_LOGf("Stop %s\n", program_id);

	if (ts.syslog_active) {
		if (ts.syslog_remote)
			log_close();
		else
			closelog();
	}

	if (ts.input_dump_file)
		fclose(ts.input_dump_file);

	if (ts.pidfile)
		unlink(ts.pidfile);

	if (log_file)
		fclose(log_file);

	notify_free(&ts.notify);
	data_free(&ts);

	exit(EXIT_SUCCESS);
}
