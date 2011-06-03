#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <dvbcsa/dvbcsa.h>

#include "libfuncs/libfuncs.h"
#include "libts/tsfuncs.h"

#include "data.h"
#include "util.h"
#include "camd.h"
#include "tables.h"

void LOG_func(const char *msg) {
	char date[64];
	struct tm tm;
	time_t now;
	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime(&now));
	fprintf(stderr, "%s | %s", date, msg);
}

void show_help(struct ts *ts) {
	printf("ts v1.0\n");
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: ts [opts] < mpeg_ts\n");
	printf("\n");
	printf("  Options:\n");
	printf("    -c ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	printf("\n");
	printf("  CAMD35 server options:\n");
	printf("    -s server_addr | default: disabled (format 1.2.3.4:2233)\n");
	printf("    -U server_user | default: %s\n", ts->camd35.user);
	printf("    -P server_pass | default: %s\n", ts->camd35.pass);
	printf("\n");
	printf("  Output options (if output is disabled stdout is used for output):\n");
	printf("    -o output_addr | default: disabled (format: 239.78.78.78:5000)\n");
	printf("    -i output_intf | default: %s\n", inet_ntoa(ts->output_intf));
	printf("    -t output_ttl  | default: %d\n", ts->output_ttl);
	printf("\n");
	printf("  Filtering options:\n");
	printf("    -e             | EMM send (default: %s).\n", ts->emm_send ? "enabled" : "disabled");
	printf("                   | - Send EMMs to CAMD server for processing.\n");
	printf("\n");
	printf("    -p             | Output PID filter (default: %s).\n", ts->pid_filter ? "enabled" : "disabled");
	printf("                   | - When PID filter is enabled only PAT/PMT/SDT/data\n");
	printf("                   | - packets are left in the output.\n");
	printf("\n");
	printf("    -D debug_level | Message debug level. Bigger levels includes the levels bellow.\n");
	printf("                   |    0 - default messages\n");
	printf("                   |    1 - show PSI tables\n");
	printf("                   |    2 - show EMMs\n");
	printf("                   |    3 - show duplicate ECMs\n");
	printf("                   |    4 - packet debug\n");
	printf("\n");
}

void parse_options(struct ts *ts, int argc, char **argv) {
	int j, ca_err = 0, server_err = 1, output_addr_err = 0, output_intf_err = 0;
	while ((j = getopt(argc, argv, "cFs:o:i:t:U:P:epD:h")) != -1) {
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

			case 'o':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					ts->output_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &ts->output_addr) == 0)
					output_addr_err = 1;
				break;
			case 'i':
				if (inet_aton(optarg, &ts->output_intf) == 0)
					output_intf_err = 1;
				break;
			case 't':
				ts->output_ttl = atoi(optarg);
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
	if (ca_err || server_err) {
		show_help(ts);
		if (ca_err)
			fprintf(stderr, "ERROR: Requested CA system is unsupported.\n");
		if (server_err)
			fprintf(stderr, "ERROR: Server IP address is not set or it is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output IP address is invalid.\n");
		if (output_intf_err)
			fprintf(stderr, "ERROR: Output interface address is invalid.\n");
		exit(1);
	}
	ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
	ts_LOGf("Server addr: %s:%u\n", inet_ntoa(ts->camd35.server_addr), ts->camd35.server_port);
	ts_LOGf("Server user: %s\n", ts->camd35.user);
	ts_LOGf("Server pass: %s\n", ts->camd35.pass);
	if (ts->output_port) {
		ts_LOGf("Output addr: %s:%u\n", inet_ntoa(ts->output_addr), ts->output_port);
		ts_LOGf("Output intf: %s\n", inet_ntoa(ts->output_intf));
		ts_LOGf("Output ttl : %d\n", ts->output_ttl);
	}
	ts_LOGf("EMM send   : %s\n", ts->emm_send   ? "enabled" : "disabled");
	ts_LOGf("PID filter : %s\n", ts->pid_filter ? "enabled" : "disabled");
}


static unsigned long ts_pack;
static int ts_pack_shown;

void show_ts_pack(struct ts *ts, uint16_t pid, char *wtf, char *extra, uint8_t *ts_packet) {
	char cw1_dump[8 * 6];
	char cw2_dump[8 * 6];
	if (ts->debug_level >= 4) {
		if (ts_pack_shown)
			return;
		int stype = ts_packet_get_scrambled(ts_packet);
		ts_hex_dump_buf(cw1_dump, 8 * 6, ts->key.cw    , 8, 0);
		ts_hex_dump_buf(cw2_dump, 8 * 6, ts->key.cw + 8, 8, 0);
		fprintf(stderr, "@ %s %s %03x %5ld %7ld | %s   %s | %s\n",
			stype == 0 ? "------" :
			stype == 2 ? "even 0" :
			stype == 3 ? "odd  1" : "??????",
			wtf,
			pid,
			ts_pack, ts_pack * 188,
			cw1_dump, cw2_dump, extra ? extra : wtf);
	}
}

void dump_ts_pack(struct ts *ts, uint16_t pid, uint8_t *ts_packet) {
	if (pid == 0x010)		show_ts_pack(ts, pid, "nit", NULL, ts_packet);
	else if (pid == 0x11)	show_ts_pack(ts, pid, "sdt", NULL, ts_packet);
	else if (pid == 0x12)	show_ts_pack(ts, pid, "epg", NULL, ts_packet);
	else					show_ts_pack(ts, pid, "---", NULL, ts_packet);
}

void ts_process_packets(struct ts *ts, uint8_t *data, ssize_t data_len) {
	ssize_t i;
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);

		ts_pack_shown = 0;

		process_pat(ts, pid, ts_packet);
		process_cat(ts, pid, ts_packet);
		process_pmt(ts, pid, ts_packet);
		process_emm(ts, pid, ts_packet);
		process_ecm(ts, pid, ts_packet);

		if (!ts_pack_shown)
			dump_ts_pack(ts, pid, ts_packet);

		int scramble_idx = ts_packet_get_scrambled(ts_packet);
		if (scramble_idx > 1) {
			if (ts->key.is_valid_cw) {
				// scramble_idx 2 == even key
				// scramble_idx 3 == odd key
				ts_packet_set_not_scrambled(ts_packet);
				dvbcsa_decrypt(ts->key.csakey[scramble_idx - 2], ts_packet + 4, 184);
			} else {
				// Can't decrypt the packet just make it NULL packet
				if (ts->pid_filter)
					ts_packet_set_pid(ts_packet, 0x1fff);
			}
		}

		ts_pack++;
	}
}

void ts_write_packets(struct ts *ts, uint8_t *data, ssize_t data_len) {
	ssize_t i;
	for (i=0; i<data_len; i += 188) {
		uint8_t *ts_packet = data + i;
		uint16_t pid = ts_packet_get_pid(ts_packet);
		if (ts->pid_filter) {
			if (pidmap_get(&ts->pidmap, pid)) // PAT or allowed PIDs
				write(1, ts_packet, 188);
		} else {
			write(1, ts_packet, 188);
		}
	}
}

#define FRAME_SIZE (188 * 7)

int main(int argc, char **argv) {
	ssize_t readen;
	uint8_t ts_packet[FRAME_SIZE];
	struct ts ts;

	ts_set_log_func(LOG_func);

	data_init(&ts);

	parse_options(&ts, argc, argv);

	camd35_connect(&ts.camd35);
	do {
		readen = read(0, ts_packet, FRAME_SIZE);
		if (readen > 0) {
			ts_process_packets(&ts, ts_packet, readen);
			ts_write_packets(&ts, ts_packet, readen);
		}
	} while (readen > 0);
	camd35_disconnect(&ts.camd35);

	data_free(&ts);

	exit(0);
}
