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

struct key key;

int debug_level = 0;
unsigned long ts_pack = 0;
int ts_pack_shown = 0;

enum CA_system req_CA_sys = CA_CONNAX;
struct in_addr camd35_server_addr;
unsigned int camd35_server_port = 2233;
char *camd35_user = "user";
char *camd35_pass = "pass";
uint32_t camd35_auth = 0;

int emm_send = 1;
int pid_filter = 0;

struct in_addr output_addr;
unsigned int output_port;
int output_ttl = 1;
struct in_addr output_intf;

void show_help() {
	printf("TSDECRYPT v1.0\n");
	printf("Copyright (c) 2011 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: tsdecrypt [opts] < mpeg_ts\n");
	printf("\n");
	printf("  Options:\n");
	printf("    -c ca_system   | default: %s valid: IRDETO, CONNAX, CRYPTOWORKS\n", ts_get_CA_sys_txt(req_CA_sys));
	printf("\n");
	printf("  CAMD35 server options:\n");
	printf("    -s server_addr | default: disabled (format 1.2.3.4:2233)\n");
	printf("    -U server_user | default: %s\n", camd35_user);
	printf("    -P server_pass | default: %s\n", camd35_pass);
	printf("\n");
	printf("  Output options (if output is disabled stdout is used for output):\n");
	printf("    -o output_addr | default: disabled (format: 239.78.78.78:5000)\n");
	printf("    -i output_intf | default: %s\n", inet_ntoa(output_intf));
	printf("    -t output_ttl  | default: %d\n", output_ttl);
	printf("\n");
	printf("  Filtering options:\n");
	printf("    -e             | EMM send (default: %s).\n", emm_send ? "enabled" : "disabled");
	printf("                   | - Send EMMs to CAMD server for processing.\n");
	printf("\n");
	printf("    -p             | Output PID filter (default: %s).\n", pid_filter ? "enabled" : "disabled");
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

void parse_options(int argc, char **argv) {
	int j, ca_err = 0, server_err = 1, output_addr_err = 0, output_intf_err = 0;
	while ((j = getopt(argc, argv, "cFs:o:i:t:U:P:epD:h")) != -1) {
		char *p = NULL;
		switch (j) {
			case 'c':
				if (strcasecmp("IRDETO", optarg) == 0)
					req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0)
					req_CA_sys = CA_CONNAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					req_CA_sys = CA_CRYPTOWORKS;
				else
					ca_err = 1;
				break;

			case 's':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					camd35_server_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &camd35_server_addr) == 0)
					server_err = 1;
				else
					server_err = 0;
				break;

			case 'o':
				p = strrchr(optarg, ':');
				if (p) {
					*p = 0x00;
					output_port = atoi(p + 1);
				}
				if (inet_aton(optarg, &output_addr) == 0)
					output_addr_err = 1;
				break;
			case 'i':
				if (inet_aton(optarg, &output_intf) == 0)
					output_intf_err = 1;
				break;
			case 't':
				output_ttl = atoi(optarg);
				break;

			case 'U':
				camd35_user = optarg;
				break;
			case 'P':
				camd35_pass = optarg;
				break;

			case 'e':
				emm_send = !emm_send;
				break;
			case 'p':
				pid_filter = !pid_filter;
				break;

			case 'D':
				debug_level = atoi(optarg);
				break;

			case 'h':
				show_help();
				exit(0);
		}
	}
	if (ca_err || server_err) {
		show_help();
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
	ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(req_CA_sys));
	ts_LOGf("Server addr: %s:%u\n", inet_ntoa(camd35_server_addr), camd35_server_port);
	ts_LOGf("Server user: %s\n", camd35_user);
	ts_LOGf("Server pass: %s\n", camd35_pass);
	if (output_port) {
		ts_LOGf("Output addr: %s:%u\n", inet_ntoa(output_addr), output_port);
		ts_LOGf("Output intf: %s\n", inet_ntoa(output_intf));
		ts_LOGf("Output ttl : %d\n", output_ttl);
	}
	ts_LOGf("EMM send   : %s\n", emm_send   ? "enabled" : "disabled");
	ts_LOGf("PID filter : %s\n", pid_filter ? "enabled" : "disabled");
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
			dump_ts_pack(pid, ts_packet);

		int scramble_idx = ts_packet_get_scrambled(ts_packet);
		if (scramble_idx > 1) {
			if (key.is_valid_cw) {
				// scramble_idx 2 == even key
				// scramble_idx 3 == odd key
				ts_packet_set_not_scrambled(ts_packet);
				dvbcsa_decrypt(key.csakey[scramble_idx - 2], ts_packet + 4, 184);
			} else {
				// Can't decrypt the packet just make it NULL packet
				if (pid_filter)
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
		if (pid_filter) {
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

	memset(&key, 0, sizeof(key));
	key.csakey[0] = dvbcsa_key_alloc();
	key.csakey[1] = dvbcsa_key_alloc();

	ts_set_log_func(LOG_func);

	parse_options(argc, argv);

	camd35_connect();

	struct ts *ts = ts_alloc();
	do {
		readen = read(0, ts_packet, FRAME_SIZE);
		if (readen > 0) {
			ts_process_packets(ts, ts_packet, readen);
			ts_write_packets(ts, ts_packet, readen);
		}
	} while (readen > 0);
	ts_free(&ts);

	dvbcsa_key_free(key.csakey[0]);
	dvbcsa_key_free(key.csakey[1]);

	camd35_disconnect();
	exit(0);
}
