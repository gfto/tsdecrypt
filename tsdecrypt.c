#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "data.h"
#include "util.h"
#include "camd.h"
#include "process.h"
#include "udp.h"

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
	printf("tsdecrypt v1.0\n");
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: tsdecrypt [opts]\n");
	printf("\n");
	printf("  Input options:\n");
	printf("    -I input       | Where to read from. Supports files and multicast\n");
	printf("                   |    -I 224.0.0.1:5000 (multicast receive)\n");
	printf("                   |    -I file.ts        (read from file)\n");
	printf("                   |    -I -              (read from STDIN, the default)\n");
	printf("\n");
	printf("    -c ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	printf("\n");
	printf("  Output options:\n");
	printf("    -O output      | Where to send output. Supports files and multicast\n");
	printf("                   |    -O 239.0.0.1:5000 (multicast send)\n");
	printf("                   |    -O file.ts        (write to file)\n");
	printf("                   |    -O -              (write to STDOUT, the default)\n");
	printf("\n");
	printf("    -i output_intf | default: %s\n", inet_ntoa(ts->output.intf));
	printf("    -t output_ttl  | default: %d\n", ts->output.ttl);
	printf("\n");
	printf("  CAMD35 server options:\n");
	printf("    -s server_addr | default: disabled (format 1.2.3.4:2233)\n");
	printf("    -U server_user | default: %s\n", ts->camd35.user);
	printf("    -P server_pass | default: %s\n", ts->camd35.pass);
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
	int j, ca_err = 0, server_err = 1, input_addr_err = 0, output_addr_err = 0, output_intf_err = 0;
	while ((j = getopt(argc, argv, "cFs:I:O:i:t:U:P:epD:h")) != -1) {
		char *p = NULL;
		switch (j) {
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
			case 'O':
				output_addr_err = parse_io_param(&ts->output, optarg,
					O_CREAT | O_WRONLY | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				break;

			case 'i':
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
	if (ca_err || server_err || input_addr_err || output_addr_err || ts->input.type == WTF_IO || ts->output.type == WTF_IO) {
		show_help(ts);
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
	ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	if (ts->input.type == NET_IO) {
		ts_LOGf("Input addr : udp://%s:%u/\n", inet_ntoa(ts->input.addr), ts->input.port);
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
	ts_LOGf("EMM send   : %s\n", ts->emm_send   ? "enabled" : "disabled");
	ts_LOGf("PID filter : %s\n", ts->pid_filter ? "enabled" : "disabled");
}

int main(int argc, char **argv) {
	ssize_t readen;
	uint8_t ts_packet[FRAME_SIZE];
	struct ts ts;

	ts_set_log_func(LOG_func);

	data_init(&ts);

	parse_options(&ts, argc, argv);

	if (ts.input.type == NET_IO && udp_connect_input(&ts.input) < 1)
		goto EXIT;
	if (ts.output.type == NET_IO && udp_connect_output(&ts.output) < 1)
		goto EXIT;

	ts.threaded = !(ts.input.type == FILE_IO && ts.input.fd != 0);

	if (&ts.threaded) {
		pthread_create(&ts.decode_thread, NULL, &decode_thread, &ts);
		pthread_create(&ts.write_thread, NULL , &write_thread , &ts);
	}

	camd_start(&ts);
	do {
		readen = read(ts.input.fd, ts_packet, FRAME_SIZE);
		if (readen > 0)
			process_packets(&ts, ts_packet, readen);
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

	exit(0);
}
