/*
 * tsdecrypt
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

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"
#include "process.h"
#include "udp.h"
#include "notify.h"

#define FIRST_REPORT_SEC 3

#define PROGRAM_NAME "tsdecrypt"
static const char *program_id = PROGRAM_NAME " v" VERSION " (" GIT_VER ", build " BUILD_ID ")";

static int keep_running = 1;

static void LOG_func(const char *msg) {
	char date[64];
	struct tm tm;
	time_t now;
	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime(&now));
	fprintf(stderr, "%s | %s", date, msg);
}

static void LOG_func_syslog(const char *msg) {
	syslog(LOG_INFO, msg, strlen(msg));
}

/* The following routine is taken from benchbitslice in libdvbcsa */
void run_benchmark(void) {
	struct timeval t0, t1;
	struct dvbcsa_bs_key_s *ffkey = dvbcsa_bs_key_alloc();
	unsigned int n, i, c = 0, pkt_len = 0;
	unsigned int gs = dvbcsa_bs_batch_size();
	uint8_t data[gs + 1][184];
	struct dvbcsa_bs_batch_s pcks[gs + 1];
	uint8_t cw[8] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, };

	srand(time(0));

	puts("* Single threaded libdvbcsa benchmark *");

	dvbcsa_bs_key_set (cw, ffkey);

	printf(" - Generating batch with %i randomly sized packets\n\n", gs);
	for (i = 0; i < gs; i++) {
		pcks[i].data = data[i];
		pcks[i].len = 100 + rand() % 85;
		memset(data[i], rand(), pcks[i].len);
		pkt_len += pcks[i].len;
	}
	pcks[i].data = NULL;

	gettimeofday(&t0, NULL);
	for (n = (1 << 12) / gs; n < (1 << 19) / gs; n *= 2) {
		printf(" - Decrypting %u TS packets\n", n * gs);
		for (i = 0; i < n; i++) {
			dvbcsa_bs_decrypt(ffkey, pcks, 184);
		}
		c += n * gs;
	}
	gettimeofday(&t1, NULL);

	printf("\n* %u packets proceded: %.1f Mbits/s\n\n", c,
		(float)(c * 188 * 8) / (float)timeval_diff_usec(&t0, &t1)
		/*(float)((t1.tv_sec * 1000000 + t1.tv_usec) - (t0.tv_sec * 1000000 + t0.tv_usec)) */
	);

	dvbcsa_bs_key_free(ffkey);

	puts("* Done *");
}

// Unused short options: FQTYakmnqruv0123456789
static const struct option long_options[] = {
	{ "ident",				required_argument, NULL, 'i' },
	{ "daemon",				required_argument, NULL, 'd' },
	{ "syslog",				no_argument,       NULL, 'S' },
	{ "syslog-host",		required_argument, NULL, 'l' },
	{ "syslog-port",		required_argument, NULL, 'L' },
	{ "notify-program",		required_argument, NULL, 'N' },

	{ "input",				required_argument, NULL, 'I' },
	{ "input-rtp",			no_argument,       NULL, 'R' },
	{ "input-ignore-disc",	no_argument,       NULL, 'z' },
	{ "input-service",		required_argument, NULL, 'M' },
	{ "input-dump",			required_argument, NULL, 'W' },

	{ "output",				required_argument, NULL, 'O' },
	{ "output-intf",		required_argument, NULL, 'o' },
	{ "output-ttl",			required_argument, NULL, 't' },
	{ "output-tos",			required_argument, NULL, 'g' },
	{ "output-filter",		no_argument,       NULL, 'p' },
	{ "no-output-filter",	no_argument,       NULL, 'p' },
	{ "output-nit-pass",	no_argument,       NULL, 'y' },
	{ "output-eit-pass",	no_argument,       NULL, 'w' },
	{ "output-tdt-pass",	no_argument,       NULL, 'x' },

	{ "ca-system",			required_argument, NULL, 'c' },
	{ "caid",				required_argument, NULL, 'C' },

	{ "camd-proto",			required_argument, NULL, 'A' },
	{ "camd-server",		required_argument, NULL, 's' },
	{ "camd-user",			required_argument, NULL, 'U' },
	{ "camd-pass",			required_argument, NULL, 'P' },
	{ "camd-des-key",		required_argument, NULL, 'B' },

	{ "emm",				no_argument,       NULL, 'e' },
	{ "emm-pid",			required_argument, NULL, 'Z' },
	{ "emm-only",			no_argument,       NULL, 'E' },
	{ "emm-report-time",	required_argument, NULL, 'f' },

	{ "ecm-pid",			required_argument, NULL, 'X' },
	{ "ecm-report-time",	required_argument, NULL, 'H' },
	{ "ecm-irdeto-type",	required_argument, NULL, 'G' },
	{ "ecm-no-log",			no_argument      , NULL, 'K' },
	{ "cw-warn-time",		required_argument, NULL, 'J' },

	{ "debug",				required_argument, NULL, 'D' },
	{ "pid-report",			no_argument,       NULL, 'j' },
	{ "bench",				no_argument,       NULL, 'b' },
	{ "help",				no_argument,       NULL, 'h' },
	{ "version",			no_argument,       NULL, 'V' },

	{ 0, 0, 0, 0 }
};

static void show_help(struct ts *ts) {
	printf("%s\n", program_id);
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: " PROGRAM_NAME " [opts]\n");
	printf("\n");
	printf("Daemon options:\n");
	printf(" -i --ident <server>        | Format PROVIDER/CHANNEL. Default: empty\n");
	printf(" -d --daemon <pidfile>      | Daemonize program and write pid file.\n");
	printf(" -N --notify-program <prg>  | Execute <prg> to report events. Default: empty\n");
	printf("\n");
	printf(" -S --syslog                | Log messages using syslog.\n");
	printf(" -l --syslog-host <host>    | Syslog server address. Default: disabled\n");
	printf(" -L --syslog-port <port>    | Syslog server port. Default: %d\n", ts->syslog_port);
	printf("\n");
	printf("Input options:\n");
	printf(" -I --input <source>        | Where to read from. File or multicast address.\n");
	printf("                            .    -I 224.0.0.1:5000 (multicast receive)\n");
	printf("                            .    -I file.ts        (read from file)\n");
	printf("                            .    -I -              (read from stdin) (default)\n");
	printf(" -R --input-rtp             | Enable RTP input\n");
	printf(" -z --input-ignore-disc     | Do not report discontinuty errors in input.\n");
	printf(" -M --input-service <srvid> | Choose service id when input is MPTS.\n");
	printf(" -W --input-dump <filename> | Save input stream in file.\n");
	printf("\n");
	printf("Output options:\n");
	printf(" -O --output <dest>         | Where to send output. File or multicast address.\n");
	printf("                            .    -O 239.0.0.1:5000 (multicast send)\n");
	printf("                            .    -O file.ts        (write to file)\n");
	printf("                            .    -O -              (write to stdout) (default)\n");
	printf(" -o --output-intf <addr>    | Set multicast output interface. Default: %s\n", inet_ntoa(ts->output.intf));
	printf(" -t --output-ttl <ttl>      | Set multicast ttl. Default: %d\n", ts->output.ttl);
	printf(" -g --output-tos <tos>      | Set TOS value of output packets. Default: none\n");
	printf(" -p --no-output-filter      | Disable output filtering. Default: %s\n", ts->pid_filter ? "enabled" : "disabled");
	printf(" -y --output-nit-pass       | Pass through NIT.\n");
	printf(" -w --output-eit-pass       | Pass through EIT (EPG).\n");
	printf(" -x --output-tdt-pass       | Pass through TDT/TOT.\n");
	printf("\n");
	printf("CA options:\n");
	printf(" -c --ca-system <ca_sys>    | Process input EMM/ECM from <ca_sys>.\n");
	printf("                            | Valid systems are: CONAX (default), CRYPTOWORKS,\n");
	printf("                            .   IRDETO, SECA (MEDIAGUARD), VIACCESS,\n");
	printf("                            .   VIDEOGUARD (NDS), NAGRA and DRECRYPT.\n");
	printf(" -C --caid <caid>           | Set CAID. Default: Taken from --ca-system.\n");
	printf("\n");
	printf("CAMD server options:\n");
	printf(" -A --camd-proto <proto>    | Set CAMD network protocol.\n");
	printf("                            . Valid protocols are: CS378X (default) and NEWCAMD\n");
	printf(" -s --camd-server <addr>    | Set CAMD server ip_address:port (1.2.3.4:2233).\n");
	printf(" -U --camd-user <user>      | Set CAMD server user. Default: %s\n", ts->camd.user);
	printf(" -P --camd-pass <pass>      | Set CAMD server password. Default: %s\n", ts->camd.pass);
	printf(" -B --camd-des-key <key>    | Set DES key for newcamd protocol.\n");
	printf("                            . Default: %s\n", ts->camd.newcamd.hex_des_key);
	printf("\n");
	printf("EMM options:\n");
	printf(" -e --emm                   | Enable sending EMM's to CAMD. Default: %s\n", ts->emm_send ? "enabled" : "disabled");
	printf(" -E --emm-only              | Send only EMMs to CAMD, skipping ECMs and without\n");
	printf("                            .   decoding the input stream.\n");
	printf(" -Z --emm-pid <pid>         | Force EMM pid. Default: none\n");
	printf(" -f --emm-report-time <sec> | Report each <sec> seconds how much EMMs have been\n");
	printf("                            .   received/processed. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->emm_report_interval);
	printf("\n");
	printf("ECM options:\n");
	printf(" -X --ecm-pid <pid>         | Force ECM pid. Default: none\n");
	printf(" -H --ecm-report-time <sec> | Report each <sec> how much ECMs and CWs have been\n");
	printf("                            .   processed/skipped. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->ecm_report_interval);
	printf(" -G --ecm-irdeto-type <int> | Process IRDETO ECMs with type X /0-3/. Default: %d\n", ts->irdeto_ecm);
	printf(" -K --ecm-no-log            | Disable ECM and code words logging.\n");
	printf(" -J --cw-warn-time <sec>    | Warn if no valid code word has been received.\n");
	printf("                            .   Set <sec> to 0 to disable. Default: %d sec\n", ts->cw_warn_sec);
	printf("\n");
	printf("Misc options:\n");
	printf(" -D --debug <level>         | Message debug level.\n");
	printf("                            .    0 = default messages\n");
	printf("                            .    1 = show PSI tables\n");
	printf("                            .    2 = show EMMs\n");
	printf("                            .    3 = show duplicate ECMs\n");
	printf("                            .    4 = packet debug\n");
	printf("                            .    5 = packet debug + packet dump\n");
	printf(" -j --pid-report            | Report how much packets were received.\n");
	printf(" -b --bench                 | Benchmark decrypton.\n");
	printf(" -h --help                  | Show help screen.\n");
	printf(" -V --version               | Show program version.\n");
	printf("\n");
}

static int parse_io_param(struct io *io, char *opt, int open_flags, mode_t open_mode) {
	io->type = WTF_IO;
	char *p = strrchr(opt, ':');
	if (!p) {
		io->type = FILE_IO;
		if (strcmp(opt, "-") != 0) {
			io->fd = open(opt, open_flags, open_mode);
			if (io->fd < 0) {
				fprintf(stderr, "ERROR: Can not open file (%s): %s\n", opt, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		io->fname = strdup(opt);
		return 0;
	}
	*p = 0x00;
	io->type = NET_IO;
	io->port = atoi(p + 1);
	if (inet_aton(opt, &io->addr) == 0)
		return 1;
	return 0;
}

static void parse_options(struct ts *ts, int argc, char **argv) {
	int j, i, ca_err = 0, server_err = 1, input_addr_err = 0, output_addr_err = 0, output_intf_err = 0, ident_err = 0, port_set = 0;
	while ( (j = getopt_long(argc, argv, "i:d:N:Sl:L:I:RzM:W:O:o:t:g:pwxyc:C:A:s:U:P:B:eZ:Ef:X:H:G:KJ:D:jbhV", long_options, NULL)) != -1 ) {
		char *p = NULL;
		switch (j) {
			case 'i':
				strncpy(ts->ident, optarg, sizeof(ts->ident) - 1);
				ts->ident[sizeof(ts->ident) - 1] = 0;
				break;
			case 'd':
				strncpy(ts->pidfile, optarg, sizeof(ts->pidfile) - 1);
				ts->pidfile[sizeof(ts->pidfile) - 1] = 0;
				ts->daemonize = 1;
				break;
			case 'N':
				strncpy(ts->notify_program, optarg, sizeof(ts->notify_program) - 1);
				ts->notify_program[sizeof(ts->notify_program) - 1] = 0;
				break;

			case 'S':
				ts->syslog_active = 1;
				ts->syslog_remote = 0;
				break;
			case 'l':
				strncpy(ts->syslog_host, optarg, sizeof(ts->syslog_host) - 1);
				ts->syslog_host[sizeof(ts->syslog_host) - 1] = 0;
				ts->syslog_active = 1;
				ts->syslog_remote = 1;
				break;
			case 'L':
				ts->syslog_port = atoi(optarg);
				break;

			case 'I':
				input_addr_err = parse_io_param(&ts->input, optarg, O_RDONLY, 0);
				break;
			case 'R':
				ts->rtp_input = !ts->rtp_input;
				break;
			case 'z':
				ts->ts_discont = !ts->ts_discont;
				break;
			case 'M':
				ts->forced_service_id = strtoul(optarg, NULL, 0) & 0xffff;
				break;
			case 'W':
				ts->input_dump_filename = optarg;
				break;

			case 'O':
				output_addr_err = parse_io_param(&ts->output, optarg,
					O_CREAT | O_WRONLY | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				break;
			case 'o':
				if (inet_aton(optarg, &ts->output.intf) == 0)
					output_intf_err = 1;
				break;
			case 't':
				ts->output.ttl = atoi(optarg);
				break;
			case 'g':
				ts->output.tos = (uint8_t)strtol(optarg, NULL, 0);
				break;
			case 'p':
				ts->pid_filter = 0;
				break;
			case 'y':
				ts->nit_passthrough = !ts->nit_passthrough;
				break;
			case 'w':
				ts->eit_passthrough = !ts->eit_passthrough;
				break;
			case 'x':
				ts->tdt_passthrough = !ts->tdt_passthrough;
				break;
			case 'c':
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
				else
					ca_err = 1;
				break;
			case 'C':
				ts->forced_caid = strtoul(optarg, NULL, 0) & 0xffff;
				break;

			case 'A':
				if (strcasecmp(optarg, "cs378x") == 0) {
					camd_proto_cs378x(&ts->camd.ops);
				} else if (strcasecmp(optarg, "newcamd") == 0) {
					camd_proto_newcamd(&ts->camd.ops);
				} else {
					fprintf(stderr, "Unknown CAMD protocol: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 's':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					ts->camd.server_port = atoi(p + 1);
					port_set = 1;
				}
				if (inet_aton(optarg, &ts->camd.server_addr) == 0)
					server_err = 1;
				else
					server_err = 0;
				break;
			case 'U':
				strncpy(ts->camd.user, optarg, sizeof(ts->camd.user) - 1);
				ts->camd.user[sizeof(ts->camd.user) - 1] = 0;
				break;
			case 'P':
				strncpy(ts->camd.pass, optarg, sizeof(ts->camd.pass) - 1);
				ts->camd.pass[sizeof(ts->camd.pass) - 1] = 0;
				break;
			case 'B':
				if (strlen(optarg) != DESKEY_LENGTH) {
					fprintf(stderr, "ERROR: des key should be %u characters long.\n", DESKEY_LENGTH);
					exit(EXIT_FAILURE);
				}
				strncpy(ts->camd.newcamd.hex_des_key, optarg, sizeof(ts->camd.newcamd.hex_des_key) - 1);
				ts->camd.newcamd.hex_des_key[sizeof(ts->camd.newcamd.hex_des_key) - 1] = 0;
				break;

			case 'e':
				ts->emm_send = !ts->emm_send;
				break;
			case 'Z':
				ts->forced_emm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'E':
				ts->emm_only = 1;
				ts->emm_send = 1;
				break;
			case 'f':
				ts->emm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->emm_report_interval > 86400)
					ts->emm_report_interval = 86400;
				break;

			case 'X':
				ts->forced_ecm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'H':
				ts->ecm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->ecm_report_interval > 86400)
					ts->ecm_report_interval = 86400;
				break;
			case 'G':
				ts->irdeto_ecm = atoi(optarg);
				break;
			case 'K':
				ts->ecm_cw_log = !ts->ecm_cw_log;
				break;
			case 'J':
				ts->cw_warn_sec = strtoul(optarg, NULL, 10);
				if (ts->cw_warn_sec > 86400)
					ts->cw_warn_sec = 86400;
				break;

			case 'D':
				ts->debug_level = atoi(optarg);
				break;
			case 'j':
				ts->pid_report = 1;
				break;
			case 'b':
				run_benchmark();
				exit(EXIT_SUCCESS);

			case 'h':
				show_help(ts);
				exit(EXIT_SUCCESS);

			case 'V':
				printf("%s\n", program_id);
				exit(EXIT_SUCCESS);
		}
	}
	if (!ts->ident[0]) {
		if (ts->syslog_active || ts->notify_program[0])
			ident_err = 1;
	}
	if (ident_err || ca_err || server_err || input_addr_err || output_addr_err || ts->input.type == WTF_IO || ts->output.type == WTF_IO) {
		show_help(ts);
		if (ident_err)
			fprintf(stderr, "ERROR: Ident is not set, please use --ident option.\n");
		if (ca_err)
			fprintf(stderr, "ERROR: Requested CA system is unsupported.\n");
		if (server_err)
			fprintf(stderr, "ERROR: CAMD server IP address is not set or it is invalid.\n");
		if (input_addr_err)
			fprintf(stderr, "ERROR: Input IP address is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output IP address is invalid.\n");
		if (output_intf_err)
			fprintf(stderr, "ERROR: Output interface address is invalid.\n");
		exit(EXIT_FAILURE);
	}
	if (decode_hex_string(ts->camd.newcamd.hex_des_key, ts->camd.newcamd.bin_des_key, DESKEY_LENGTH) < 0) {
		fprintf(stderr, "ERROR: Invalid hex string for des key: %s\n", ts->camd.newcamd.hex_des_key);
		exit(EXIT_FAILURE);
	}
	if (ts->camd.ops.proto == CAMD_NEWCAMD && !port_set) {
		fprintf(stderr, "ERROR: CAMD server port is not set. Use --camd-server %s:xxxx to set the port.\n", inet_ntoa(ts->camd.server_addr));
		exit(EXIT_FAILURE);
	}

	ts_LOGf("Ident      : %s\n", ts->ident[0] ? ts->ident : "*NOT SET*");
	ts_LOGf("Notify prog: %s\n", ts->notify_program[0] ? ts->notify_program : "*NOT SET*");
	if (ts->pidfile[0])
		ts_LOGf("Daemonize  : %s pid file.\n", ts->pidfile);
	else
		ts_LOGf("Daemonize  : no daemon\n");
	if (ts->syslog_active) {
		if (ts->syslog_remote)
			ts_LOGf("Syslog     : %s:%d\n", ts->syslog_host, ts->syslog_port);
		else
			ts_LOGf("Syslog     : enabled\n");
	} else
		ts_LOGf("Syslog     : disabled\n");

	if (ts->forced_caid)
		ts->req_CA_sys = ts_get_CA_sys(ts->forced_caid);
	if (!ts->forced_caid)
		ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	else
		ts_LOGf("CA System  : %s | CAID: 0x%04x (%d)\n",
			ts_get_CA_sys_txt(ts->req_CA_sys),
			ts->forced_caid, ts->forced_caid);

	if (ts->input.type == NET_IO) {
		ts_LOGf("Input addr : %s://%s:%u/\n",
			ts->rtp_input ? "rtp" : "udp",
			inet_ntoa(ts->input.addr), ts->input.port);
	} else if (ts->input.type == FILE_IO) {
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

	if (!ts->emm_only)
	{
		if (ts->output.type == NET_IO) {
			ts_LOGf("Output addr: udp://%s:%u/\n", inet_ntoa(ts->output.addr), ts->output.port);
			ts_LOGf("Output intf: %s\n", inet_ntoa(ts->output.intf));
			ts_LOGf("Output ttl : %d\n", ts->output.ttl);
			if (ts->output.tos > -1)
				ts_LOGf("Output TOS : %u (0x%02x)\n", ts->output.tos, ts->output.tos);
		} else if (ts->output.type == FILE_IO) {
			ts_LOGf("Output file: %s\n", ts->output.fd == 1 ? "STDOUT" : ts->output.fname);
		}
		ts_LOGf("Out filter : %s (%s)\n",
			ts->pid_filter ? "enabled" : "disabled",
			ts->pid_filter ? "output only service related PIDs" : "output everything"
		);
		if (ts->pid_filter) {
			if (ts->nit_passthrough)
				ts_LOGf("Out filter : Pass through NIT.\n");
			if (ts->eit_passthrough)
				ts_LOGf("Out filter : Pass through EIT (EPG).\n");
			if (ts->tdt_passthrough)
				ts_LOGf("Out filter : Pass through TDT/TOT.\n");
		}
	}
	ts_LOGf("CAMD proto : %s\n", ts->camd.ops.ident);
	ts_LOGf("CAMD addr  : tcp://%s:%u/\n", inet_ntoa(ts->camd.server_addr), ts->camd.server_port);
	ts_LOGf("CAMD user  : %s\n", ts->camd.user);
	ts_LOGf("CAMD pass  : %s\n", ts->camd.pass);
	if (ts->camd.ops.proto == CAMD_NEWCAMD)
		ts_LOGf("CAMD deskey: %s\n", ts->camd.newcamd.hex_des_key);

	ts_LOGf("TS discont : %s\n", ts->ts_discont ? "report" : "ignore");
	ts->threaded = !(ts->input.type == FILE_IO && ts->input.fd != 0);
	if (ts->emm_send && ts->emm_report_interval)
		ts_LOGf("EMM report : %d sec\n", ts->emm_report_interval);
	if (ts->emm_send && ts->emm_report_interval == 0)
		ts_LOGf("EMM report : disabled\n");
	if (ts->forced_emm_pid)
		ts_LOGf("EMM pid    : 0x%04x (%d)\n", ts->forced_emm_pid, ts->forced_emm_pid);
	if (ts->emm_only) {
		ts_LOGf("EMM only   : %s\n", ts->emm_only ? "yes" : "no");
	} else {
		ts_LOGf("EMM send   : %s\n", ts->emm_send   ? "enabled" : "disabled");
		ts_LOGf("Decoding   : %s\n", ts->threaded ? "threaded" : "single thread");
	}

	if (!ts->emm_only && ts->ecm_report_interval)
		ts_LOGf("ECM report : %d sec\n", ts->emm_report_interval);
	if (!ts->emm_only && ts->ecm_report_interval == 0)
		ts_LOGf("ECM report : disabled\n");
	if (ts->forced_ecm_pid)
		ts_LOGf("ECM pid    : 0x%04x (%d)\n", ts->forced_ecm_pid, ts->forced_ecm_pid);

	if (!ts->emm_only && ts->cw_warn_sec)
		ts_LOGf("CW warning : %d sec\n", ts->cw_warn_sec);
	if (!ts->emm_only && ts->cw_warn_sec)
		ts_LOGf("CW warning : disabled\n");

	if (!ts->ecm_cw_log)
		ts_LOGf("ECM/CW log : disabled\n");

	for (i=0; i<(int)sizeof(ts->ident); i++) {
		if (!ts->ident[i])
			break;
		if (ts->ident[i] == '/')
			ts->ident[i] = '-';
	}
}

static void report_emms(struct ts *ts, time_t now) {
	ts_LOGf("EMM | Received %u and processed %u in %lu seconds.\n",
		ts->emm_seen_count,
		ts->emm_processed_count,
		now - ts->emm_last_report);
	ts->emm_last_report = now;
	ts->emm_seen_count = 0;
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
	notify(ts, "NO_CODE_WORD", "No valid code word was received for %ld sec.",
		now - ts->cw_last_warn);
	ts_LOGf("CW  | *ERR* No valid code word was received for %ld seconds!\n",
		now - ts->cw_last_warn);
	ts->cw_last_warn = now;
}

static void do_reports(struct ts *ts) {
	static int first_emm_report = 1;
	static int first_ecm_report = 1;
	time_t now = time(NULL);
	if (ts->emm_send && ts->emm_report_interval) {
		if (first_emm_report && now >= ts->emm_last_report) {
			first_emm_report = 0;
			ts->emm_last_report -= FIRST_REPORT_SEC;
			report_emms(ts, now);
		} else if ((time_t)(ts->emm_last_report + ts->emm_report_interval) <= now) {
			report_emms(ts, now);
		}
	}
	if (!ts->emm_only && ts->ecm_report_interval) {
		if (first_ecm_report && now >= ts->ecm_last_report) {
			first_ecm_report = 0;
			ts->ecm_last_report -= FIRST_REPORT_SEC;
			report_ecms(ts, now);
		} else if ((time_t)(ts->ecm_last_report + ts->ecm_report_interval) <= now) {
			report_ecms(ts, now);
		}
	}

	if (!ts->emm_only && !ts->key.is_valid_cw) {
		if ((time_t)(ts->cw_last_warn + ts->cw_warn_sec) <= now) {
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

int main(int argc, char **argv) {
	ssize_t readen;
	int have_data = 1;
	int ntimeouts = 0;
	time_t timeout_start = time(NULL);
	uint8_t ts_packet[FRAME_SIZE + RTP_HDR_SZ];
	uint8_t rtp_hdr[2][RTP_HDR_SZ];
	int rtp_hdr_pos = 0, num_packets = 0;
	struct ts ts;

	memset(rtp_hdr[0], 0, RTP_HDR_SZ);
	memset(rtp_hdr[1], 0, RTP_HDR_SZ);

	data_init(&ts);

	parse_options(&ts, argc, argv);

	if (ts.pidfile[0])
		daemonize(ts.pidfile);

	if (!ts.syslog_active) {
		ts_set_log_func(LOG_func);
	} else {
		if (ts.syslog_remote) {
			ts_set_log_func(LOG);
			log_init(ts.ident, 1, 1, ts.syslog_host, ts.syslog_port);
		} else {
			openlog(ts.ident, LOG_NDELAY | LOG_PID, LOG_USER);
			ts_set_log_func(LOG_func_syslog);
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
		pthread_create(&ts.decode_thread, NULL, &decode_thread, &ts);
		pthread_create(&ts.write_thread, NULL , &write_thread , &ts);
	}

	ts.emm_last_report = time(NULL) + FIRST_REPORT_SEC;
	ts.ecm_last_report = time(NULL) + FIRST_REPORT_SEC;
	camd_start(&ts);
	do {
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
					notify(&ts, "INPUT_TIMEOUT", "Read timeout on input %s://%s:%u/",
							ts.rtp_input ? "rtp" : "udp",
							inet_ntoa(ts.input.addr), ts.input.port);
				}
				ntimeouts++;
			} else {
				if (ntimeouts && readen > 0) {
					notify(&ts, "INPUT_OK", "Data is available on input %s://%s:%u/ after %ld seconds timeout.",
							ts.rtp_input ? "rtp" : "udp",
							inet_ntoa(ts.input.addr), ts.input.port,
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

	if (ts.daemonize)
		unlink(ts.pidfile);

	notify_free(&ts.notify);
	data_free(&ts);

	exit(EXIT_SUCCESS);
}
