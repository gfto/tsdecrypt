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

static const struct option long_options[] = {
	{ "ident",				required_argument, NULL, 'i' },
	{ "daemon",				required_argument, NULL, 'd' },
	{ "syslog-host",		required_argument, NULL, 'l' },
	{ "syslog-port",		required_argument, NULL, 'L' },
	{ "notify-program",		required_argument, NULL, 'N' },

	{ "input",				required_argument, NULL, 'I' },
	{ "input-rtp",			no_argument,       NULL, 'R' },
	{ "input-ignore-disc",	no_argument,       NULL, 'z' },

	{ "output",				required_argument, NULL, 'O' },
	{ "output-intf",		required_argument, NULL, 'o' },
	{ "output-ttl",			required_argument, NULL, 't' },
	{ "output-filter",		no_argument,       NULL, 'p' },

	{ "ca-system",			required_argument, NULL, 'c' },
	{ "caid",				required_argument, NULL, 'C' },
	{ "camd-server",		required_argument, NULL, 's' },
	{ "camd-user",			required_argument, NULL, 'U' },
	{ "camd-pass",			required_argument, NULL, 'P' },
	{ "camd-pkt-delay",		required_argument, NULL, 'y' },

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
	printf("\n");
	printf("Output options:\n");
	printf(" -O --output <dest>         | Where to send output. File or multicast address.\n");
	printf("                            .    -O 239.0.0.1:5000 (multicast send)\n");
	printf("                            .    -O file.ts        (write to file)\n");
	printf("                            .    -O -              (write to stdout) (default)\n");
	printf(" -o --output-intf <addr>    | Set multicast output interface. Default: %s\n", inet_ntoa(ts->output.intf));
	printf(" -t --output-ttl <ttl>      | Set multicast ttl. Default: %d\n", ts->output.ttl);
	printf(" -p --output-filter         | Enable or disable output filter. Default: %s\n", ts->pid_filter ? "enabled" : "disabled");
	printf("\n");
	printf("CA options:\n");
	printf(" -c --ca-system <ca_sys>    | Process input EMM/ECM from <ca_sys>.\n");
	printf("                            | Valid systems are: CONAX (default), CRYPTOWORKS,\n");
	printf("                            .   IRDETO, SECA (MEDIAGUARD), VIACCESS,\n");
	printf("                            .   VIDEOGUARD (NDS), NAGRA and DRECRYPT.\n");
	printf(" -C --caid <caid>           | Set CAID. Default: Taken from --ca-system.\n");
	printf("\n");
	printf("CAMD server options:\n");
	printf(" -s --camd-server <addr>    | Set CAMD server ip address and port (1.2.3.4:2233).\n");
	printf(" -U --camd-user <user>      | Set CAMD server user. Default: %s\n", ts->camd35.user);
	printf(" -P --camd-pass <pass>      | Set CAMD server password. Default: %s\n", ts->camd35.pass);
	printf(" -y --camd-pkt-delay <us>   | Sleep <us> usec between sending ECM/EMM\n");
	printf("                            .   packets to CAMD. Default: %d\n", ts->packet_delay);
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
	printf(" -G --ecm-irdeto-type <int> | Process IRDETO ECMs with type X /0..3/. Default: %d\n", ts->irdeto_ecm);
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
				exit(1);
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
	int j, i, ca_err = 0, server_err = 1, input_addr_err = 0, output_addr_err = 0, output_intf_err = 0, ident_err = 0;
	while ( (j = getopt_long(argc, argv, "i:d:N:l:L:I:RzO:o:t:pc:C:s:U:P:y:eZ:Ef:X:H:G:KJ:D:hV", long_options, NULL)) != -1 ) {
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

			case 'l':
				strncpy(ts->syslog_host, optarg, sizeof(ts->syslog_host) - 1);
				ts->syslog_host[sizeof(ts->syslog_host) - 1] = 0;
				ts->syslog_active = 1;
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
			case 'p':
				ts->pid_filter = !ts->pid_filter;
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

			case 's':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					ts->camd35.server_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &ts->camd35.server_addr) == 0)
					server_err = 1;
				else
					server_err = 0;
				break;
			case 'U':
				strncpy(ts->camd35.user, optarg, sizeof(ts->camd35.user) - 1);
				ts->camd35.user[sizeof(ts->camd35.user) - 1] = 0;
				break;
			case 'P':
				strncpy(ts->camd35.pass, optarg, sizeof(ts->camd35.pass) - 1);
				ts->camd35.pass[sizeof(ts->camd35.pass) - 1] = 0;
				break;
			case 'y':
				ts->packet_delay = atoi(optarg);
				if (ts->packet_delay < 0 || ts->packet_delay > 1000000)
					ts->packet_delay = 0;
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
				ts->ecm_cw_log = 0;
				break;
			case 'J':
				ts->cw_warn_sec = strtoul(optarg, NULL, 10);
				if (ts->cw_warn_sec > 86400)
					ts->cw_warn_sec = 86400;
				break;

			case 'D':
				ts->debug_level = atoi(optarg);
				break;

			case 'h':
				show_help(ts);
				exit(0);

			case 'V':
				printf("%s\n", program_id);
				exit(0);
		}
	}
	if (ts->syslog_active && !ts->ident[0])
		ident_err = 1;
	if (ident_err || ca_err || server_err || input_addr_err || output_addr_err || ts->input.type == WTF_IO || ts->output.type == WTF_IO) {
		show_help(ts);
		if (ident_err)
			fprintf(stderr, "ERROR: Syslog is enabled but ident was not set.\n");
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
		exit(1);
	}
	ts_LOGf("Ident      : %s\n", ts->ident[0] ? ts->ident : "*NOT SET*");
	ts_LOGf("Notify prog: %s\n", ts->notify_program[0] ? ts->notify_program : "*NOT SET*");
	if (ts->pidfile[0])
		ts_LOGf("Daemonize  : %s pid file.\n", ts->pidfile);
	else
		ts_LOGf("Daemonize  : no daemon\n");
	if (ts->syslog_active)
		ts_LOGf("Syslog     : %s:%d\n", ts->syslog_host, ts->syslog_port);
	else
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
	if (ts->req_CA_sys == CA_IRDETO)
		ts_LOGf("Irdeto ECM : %d\n", ts->irdeto_ecm);

	if (!ts->emm_only)
	{
		if (ts->output.type == NET_IO) {
			ts_LOGf("Output addr: udp://%s:%u/\n", inet_ntoa(ts->output.addr), ts->output.port);
			ts_LOGf("Output intf: %s\n", inet_ntoa(ts->output.intf));
			ts_LOGf("Output ttl : %d\n", ts->output.ttl);
		} else if (ts->output.type == FILE_IO) {
			ts_LOGf("Output file: %s\n", ts->output.fd == 1 ? "STDOUT" : ts->output.fname);
		}
		ts_LOGf("PID filter : %s\n", ts->pid_filter ? "enabled" : "disabled");
	}
	ts_LOGf("Server addr: tcp://%s:%u/\n", inet_ntoa(ts->camd35.server_addr), ts->camd35.server_port);
	ts_LOGf("Server user: %s\n", ts->camd35.user);
	ts_LOGf("Server pass: %s\n", ts->camd35.pass);
	if (ts->packet_delay)
		ts_LOGf("Pkt sleep  : %d us (%d ms)\n", ts->packet_delay, ts->packet_delay / 1000);
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
	ts_LOGf("CW  | *** No valid CW was received for %lu seconds!\n", now - ts->cw_last_warn);
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
		ts_set_log_func(LOG);
		log_init(ts.ident, ts.syslog_active, ts.daemonize != 1, ts.syslog_host, ts.syslog_port);
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

	if (&ts.threaded) {
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
			if (readen < 0)
				ts_LOGf("--- | Input read timeout.\n");
		} else {
			readen = read(ts.input.fd, ts_packet, FRAME_SIZE);
			have_data = !(readen <= 0);
		}
		if (readen > 0)
			process_packets(&ts, ts_packet, readen);
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

	notify(&ts, "STOP", "Stopping %s", program_id);
	ts_LOGf("Stop %s\n", program_id);

	if (ts.syslog_active)
		log_close();

	if (ts.daemonize)
		unlink(ts.pidfile);

	notify_free(&ts.notify);
	data_free(&ts);

	exit(0);
}
