/*
 * Filtering functions
 * Copyright (C) 2012 Unix Solutions Ltd.
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
#include <ctype.h>
#include <string.h>

#include "data.h"
#include "filter.h"

int filter_parse(char *filter_def, struct filter *filter) {
	int i, j, k, ret = 0;
	char *str1, *saveptr1;
	char *f = strdup(filter_def);
	memset(filter, 0, sizeof(struct filter));
	snprintf(filter->name, sizeof(filter->name), "NONAME");
	for (j = 1, str1 = f; ; j++, str1 = NULL) {
		char *token = strtok_r(str1, "/", &saveptr1);
		if (token == NULL)
			break;
		if (j == 1) { // First token, the command
			if (strstr(token, "accept_all") == token || strstr(token, "acceptall") == token) {
				filter->action = FILTER_ACCEPT_ALL;
				ret = 1;
				goto OUT; // Other tokens are not needed
			} else if (strstr(token, "reject_all") == token || strstr(token, "rejectall") == token) {
				filter->action = FILTER_REJECT_ALL;
				ret = 1;
				goto OUT; // Other tokens are not needed
			} else if (strstr(token, "accept") == token) {
				filter->action = FILTER_ACCEPT;
				continue; // Continue looking for other tokes
			} else if (strstr(token, "reject") == token) {
				filter->action = FILTER_REJECT;
				continue; // Continue looking for other tokes
			} else {
				fprintf(stderr, "ERROR: Unknown filter command: %s\n", token);
				ret = 0;
				goto OUT; // Other tokens are not needed
			}
		}
		if (j == 2) { // Second token, the settings
			char *str2, *saveptr2;
			for (k = 1, str2 = token; ; k++, str2 = NULL) {
				char *token2 = strtok_r(str2, ",", &saveptr2);
				if (token2 == NULL)
					break;
				char *eq = strrchr(token2, '=');
				if (eq) {
					if (strstr(token2, "ofs") == token2 || strstr(token2, "offset") == token2) {
						filter->offset = strtoul(eq + 1, NULL, 0);
					} else if (strstr(token2, "name") == token2) {
						snprintf(filter->name, sizeof(filter->name), "%s", eq + 1);
					} else if (strstr(token2, "data") == token2) {
						char *data = eq + 1;
						int len = strlen(data), consumed = 0;
						for (i = 0; i < len; i++) { // Parse data (01 02 03 04 ...)
							char ch = toupper(data[i]);
							// Skip 0x prefixes
							if (i + 1 < len && ch == '0' && toupper(data[i + 1]) == 'X')
								continue;
							if (!isxdigit(ch))
								continue;
							ch -= ch > 64 ? 55 : 48; // hex2dec
							if (consumed % 2 == 0) {
								filter->data[filter->data_len  ] += ch << 4;
							} else {
								filter->data[filter->data_len++] += ch;
								if (filter->data_len + 1 >= MAX_FILTER_LEN) {
									fprintf(stderr, "WARN : Too much filter data (max %d bytes), ignoring last bytes: %s\n",
										MAX_FILTER_LEN, data + i + 2);
									break;
								}
							}
							consumed++;
						}
						ret = filter->data_len;
					} else {
						fprintf(stderr, "WARN : Unknown filter setting: %s\n", token2);
					}
				}
			}
		}
	}
OUT:
	FREE(f);
	return ret;
}

void filter_dump(struct filter *filter, char *buffer, unsigned int buf_len) {
	unsigned int pos = 0;
	memset(buffer, 0, buf_len);
	pos += snprintf(buffer + pos, buf_len - pos, "Action: %s",
		filter->action == FILTER_ACCEPT_ALL ? "ACCEPT_ALL (default)" :
		filter->action == FILTER_REJECT_ALL ? "REJECT_ALL (default)" :
		filter->action == FILTER_ACCEPT     ? "ACCEPT" :
		filter->action == FILTER_REJECT     ? "REJECT" : "???");
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT)
		pos += snprintf(buffer + pos, buf_len - pos, " Name: %-20s", filter->name);
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT) {
		char tmp[MAX_FILTER_LEN * 6];
		ts_hex_dump_buf(tmp, sizeof(tmp), filter->data, filter->data_len, 0);
		pos += snprintf(buffer + pos, buf_len - pos, " Offset: %2d Data: %s", filter->offset, tmp);
	}
}

static enum filter_action filter_match(uint8_t *data, unsigned int data_len, struct filter *filter) {
	if (filter->action == FILTER_ACCEPT_ALL || filter->action == FILTER_REJECT_ALL)
		return filter->action;
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT) {
		if (filter->data_len + filter->offset > data_len)
			return FILTER_NO_MATCH;
		if (memcmp(data + filter->offset, filter->data, filter->data_len) == 0)
			return filter->action;
	}
	return FILTER_NO_MATCH;
}

int filter_match_emm(struct ts *ts, uint8_t *data, unsigned int data_len) {
	int i, ret = 1;
	for (i = 0; i < ts->emm_filters_num; i++) {
		enum filter_action result = filter_match(data, data_len, &ts->emm_filters[i]);
		switch (result) {
			case FILTER_NO_MATCH  : continue;
			case FILTER_ACCEPT_ALL: ret = 1; continue;
			case FILTER_ACCEPT    : ret = 1; break;
			case FILTER_REJECT_ALL: ret = 0; continue;
			case FILTER_REJECT    : ret = 0; break;
		}
	}
	return ret;
}
