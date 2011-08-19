#include <stdlib.h>
#include <unistd.h>
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

#define PROGRAM_NAME "tsdecrypt"
static const char *program_id = PROGRAM_NAME " " GIT_VER " build " BUILD_ID;

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

static void show_help(struct ts *ts) {
	printf("%s\n", program_id);
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: " PROGRAM_NAME " [opts]\n");
	printf("\n");
	printf("  Daemon options:\n");
	printf("    -i server_ident | Format PROVIDER/CHANNEL (default: %s)\n", ts->ident);
	printf("    -d pidfile      | Daemonize program with pid file. (default: do not daemonize)\n");
	printf("    -l syslog host  | Where is the syslog server (default: disabled)\n");
	printf("    -L Syslog port  | What is the syslog server port (default: %d)\n", ts->syslog_port);
	printf("\n");
	printf("  Input options:\n");
	printf("    -I input       | Where to read from. Supports files and multicast\n");
	printf("                   |    -I 224.0.0.1:5000 (multicast receive)\n");
	printf("                   |    -I file.ts        (read from file)\n");
	printf("                   |    -I -              (read from STDIN, the default)\n");
	printf("    -R             | Enable RTP input\n");
	printf("\n");
	printf("    -c ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	printf("    -z             | Detect discontinuty errors in input stream (default: %s).\n", ts->ts_discont ? "report" : "ignore");
	printf("\n");
	printf("  Output options:\n");
	printf("    -O output      | Where to send output. Supports files and multicast\n");
	printf("                   |    -O 239.0.0.1:5000 (multicast send)\n");
	printf("                   |    -O file.ts        (write to file)\n");
	printf("                   |    -O -              (write to STDOUT, the default)\n");
	printf("\n");
	printf("    -o output_intf | default: %s\n", inet_ntoa(ts->output.intf));
	printf("    -t output_ttl  | default: %d\n", ts->output.ttl);
	printf("\n");
	printf("  CAMD35 server options:\n");
	printf("    -s server_addr | default: disabled (format 1.2.3.4:2233)\n");
	printf("    -U server_user | default: %s\n", ts->camd35.user);
	printf("    -P server_pass | default: %s\n", ts->camd35.pass);
	printf("    -y usec_delay  | Sleep X usec between sending ECM/EMM packets to OSCAM. default: %d\n", ts->packet_delay);
	printf("\n");
	printf("  Filtering options:\n");
	printf("    -e             | EMM send (default: %s).\n", ts->emm_send ? "enabled" : "disabled");
	printf("                   | - Send EMMs to CAMD server for processing.\n");
	printf("\n");
	printf("    -p             | Output PID filter (default: %s).\n", ts->pid_filter ? "enabled" : "disabled");
	printf("                   | - When PID filter is enabled only PAT/PMT/SDT/data\n");
	printf("                   | - packets are left in the output.\n");
	printf("\n");
	printf("    -D debug_level | Message debug level.\n");
	printf("                   |    0 - default messages\n");
	printf("                   |    1 - show PSI tables\n");
	printf("                   |    2 - show EMMs\n");
	printf("                   |    3 - show duplicate ECMs\n");
	printf("                   |    4 - packet debug\n");
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
	while ((j = getopt(argc, argv, "i:d:l:L:c:s:I:O:o:t:U:P:y:ezpD:hR")) != -1) {
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
			case 'l':
				strncpy(ts->syslog_host, optarg, sizeof(ts->syslog_host) - 1);
				ts->syslog_host[sizeof(ts->syslog_host) - 1] = 0;
				ts->syslog_active = 1;
				break;
			case 'L':
				ts->syslog_port = atoi(optarg);
				break;

			case 'c':
				if (strcasecmp("IRDETO", optarg) == 0)
					ts->req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0)
					ts->req_CA_sys = CA_CONNAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					ts->req_CA_sys = CA_CRYPTOWORKS;
				else
					ca_err = 1;
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

			case 'I':
				input_addr_err = parse_io_param(&ts->input, optarg, O_RDONLY, 0);
				break;
			case 'R':
				ts->rtp_input = !ts->rtp_input;
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

			case 'z':
				ts->ts_discont = !ts->ts_discont;
				break;
			case 'e':
				ts->emm_send = !ts->emm_send;
				break;
			case 'p':
				ts->pid_filter = !ts->pid_filter;
				break;

			case 'D':
				ts->debug_level = atoi(optarg);
				break;

			case 'h':
				show_help(ts);
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
			fprintf(stderr, "ERROR: Server IP address is not set or it is invalid.\n");
		if (input_addr_err)
			fprintf(stderr, "ERROR: Input IP address is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output IP address is invalid.\n");
		if (output_intf_err)
			fprintf(stderr, "ERROR: Output interface address is invalid.\n");
		exit(1);
	}
	if (ts->ident[0])
		ts_LOGf("Ident      : %s\n", ts->ident);
	else
		ts_LOGf("Ident      : *NOT SET*\n");
	if (ts->pidfile[0])
		ts_LOGf("Daemonize  : %s pid file.\n", ts->pidfile);
	else
		ts_LOGf("Daemonize  : no daemon\n");
	if (ts->syslog_active)
		ts_LOGf("Syslog     : %s:%d\n", ts->syslog_host, ts->syslog_port);
	else
		ts_LOGf("Syslog     : disabled\n");
	ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	if (ts->input.type == NET_IO) {
		ts_LOGf("Input addr : %s://%s:%u/\n",
			ts->rtp_input ? "rtp" : "udp",
			inet_ntoa(ts->input.addr), ts->input.port);
	} else if (ts->input.type == FILE_IO) {
		ts_LOGf("Input file : %s\n", ts->input.fd == 0 ? "STDIN" : ts->input.fname);
	}
	if (ts->output.type == NET_IO) {
		ts_LOGf("Output addr: udp://%s:%u/\n", inet_ntoa(ts->output.addr), ts->output.port);
		ts_LOGf("Output intf: %s\n", inet_ntoa(ts->output.intf));
		ts_LOGf("Output ttl : %d\n", ts->output.ttl);
	} else if (ts->output.type == FILE_IO) {
		ts_LOGf("Output file: %s\n", ts->output.fd == 1 ? "STDOUT" : ts->output.fname);
	}
	ts_LOGf("Server addr: tcp://%s:%u/\n", inet_ntoa(ts->camd35.server_addr), ts->camd35.server_port);
	ts_LOGf("Server user: %s\n", ts->camd35.user);
	ts_LOGf("Server pass: %s\n", ts->camd35.pass);
	if (ts->packet_delay)
		ts_LOGf("Pkt sleep  : %d us (%d ms)\n", ts->packet_delay, ts->packet_delay / 1000);
	ts_LOGf("EMM send   : %s\n", ts->emm_send   ? "enabled" : "disabled");
	ts_LOGf("PID filter : %s\n", ts->pid_filter ? "enabled" : "disabled");
	ts_LOGf("TS discont : %s\n", ts->ts_discont ? "report" : "ignore");
	ts->threaded = !(ts->input.type == FILE_IO && ts->input.fd != 0);
	ts_LOGf("Decoding   : %s\n", ts->threaded ? "threaded" : "single thread");

	for (i=0; i<(int)sizeof(ts->ident); i++) {
		if (!ts->ident[i])
			break;
		if (ts->ident[i] == '/')
			ts->ident[i] = '-';
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

	ts_LOGf("Start %s\n", program_id);

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

	camd_start(&ts);
	do {
		if (ts.input.type == NET_IO) {
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
		} else {
			readen = read(ts.input.fd, ts_packet, FRAME_SIZE);
		}
		if (readen > 0)
			process_packets(&ts, ts_packet, readen);
		if (!keep_running)
			break;
	} while (readen > 0);
EXIT:
	camd_stop(&ts);

	if (ts.threaded) {
		ts.decode_stop = 1;
		ts.write_stop = 1;

		pthread_join(ts.decode_thread, NULL);
		pthread_join(ts.write_thread, NULL);
	}

	data_free(&ts);

	ts_LOGf("Stop %s\n", program_id);

	if (ts.syslog_active)
		log_close();

	if (ts.daemonize)
		unlink(ts.pidfile);

	exit(0);
}
