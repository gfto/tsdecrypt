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

struct filter_actions_map {
	const char			*token;
	bool				last;
	enum filter_action	type;
};

static struct filter_actions_map action_tokens[] = {
	{ "accept_all", true,  FILTER_ACCEPT_ALL },
	{ "acceptall",  true,  FILTER_ACCEPT_ALL },
	{ "reject_all", true,  FILTER_REJECT_ALL },
	{ "rejectall",  true,  FILTER_REJECT_ALL },
	{ "accept",     false, FILTER_ACCEPT     },
	{ "reject",     false, FILTER_REJECT     },
	{ NULL,         true,  FILTER_NO_MATCH   },
};

enum filter_token { T_UNKNOWN, T_NAME, T_OFFSET, T_DATA, T_MATCH, T_MASK, T_LENGTH };

struct filter_data_map {
	const char			*token;
	enum filter_token	type;
};

static struct filter_data_map data_tokens[] = {
	{ "name",    T_NAME    },
	{ "ofs",     T_OFFSET  },
	{ "offset",  T_OFFSET  },
	{ "data",    T_DATA    },
	{ "match",   T_MATCH   },
	{ "mask",    T_MASK    },
	{ "length",  T_LENGTH  },
	{ NULL,      T_UNKNOWN },
};

int parse_hex(char *data, uint8_t *output, uint8_t *output_len, uint8_t output_size) {
	int i, len = strlen(data), consumed = 0;
	uint8_t local_output_len = 0;
	if (!output_len)
		output_len = &local_output_len;
	for (i = 0; i < len; i++) { // Parse data (01 02 03 04 ...)
		char ch = toupper(data[i]);
		// Skip 0x prefixes
		if (i + 1 < len && ch == '0' && toupper(data[i + 1]) == 'X')
			continue;
		if (!isxdigit(ch))
			continue;
		ch -= ch > 64 ? 55 : 48; // hex2dec
		if (consumed % 2 == 0) {
			output[*output_len] = 0; // Reset
			output[*output_len] += ch << 4;
		} else {
			output[*output_len] += ch;
			(*output_len)++;
			if (*output_len + 1 >= output_size) {
				fprintf(stderr, "WARN : Too much filter data (max %d bytes), ignoring last bytes: %s\n",
					output_size, data + i + 2);
				break;
			}
		}
		consumed++;
	}
	return *output_len;
}

int filter_parse(char *filter_def, struct filter *filter) {
	int j, k, ret = 0;
	char *str1, *saveptr1;
	char *f = strdup(filter_def);
	memset(filter, 0, sizeof(struct filter));
	memset(filter->mask, 0xff, sizeof(filter->mask));
	snprintf(filter->name, sizeof(filter->name), "NONAME");
	for (j = 1, str1 = f; ; j++, str1 = NULL) {
		char *token = strtok_r(str1, "/", &saveptr1);
		if (token == NULL)
			break;
		if (j == 1) { // First token, the command
			struct filter_actions_map *m;
			for (m = action_tokens; m->token; m++) {
				if (strstr(token, m->token) == token) {
					filter->action = m->type;
					ret = 1;
					if (m->last)
						goto OUT; // Other tokens are not needed
					break;
				}
			}
			if (filter->action == FILTER_NO_MATCH) {
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
				char *tokdata = strrchr(token2, '=');
				if (tokdata) {
					tokdata++; // Skip =
					struct filter_data_map *m;
					enum filter_token data_type = T_UNKNOWN;
					for (m = data_tokens; m->token; m++) {
						if (strstr(token2, m->token) == token2) {
							data_type = m->type;
							break;
						}
					}
					switch (data_type) {
					case T_NAME:
						snprintf(filter->name, sizeof(filter->name), "%s", tokdata);
						break;
					case T_OFFSET:
						filter->offset = strtoul(tokdata, NULL, 0);
						break;
					case T_DATA:
						ret = parse_hex(tokdata, filter->data, &filter->filter_len, MAX_FILTER_LEN);
						break;
					case T_MATCH:
						filter->type = FILTER_TYPE_MASK;
						ret = parse_hex(tokdata, filter->data, &filter->filter_len, MAX_FILTER_LEN);
						break;
					case T_MASK:
						filter->type = FILTER_TYPE_MASK;
						ret = parse_hex(tokdata, filter->mask, NULL, MAX_FILTER_LEN);
						break;
					case T_LENGTH: {
						filter->type = FILTER_TYPE_LENGTH;
						int i;
						char *ptr, *saveptr3 = NULL;
						for (i = 0,                ptr = strtok_r(tokdata, " ", &saveptr3);
						     i < MAX_FILTER_LEN && ptr;
						     i++  ,                ptr = strtok_r(NULL, " ", &saveptr3))
						{
							filter->data[i] = strtoul(ptr, NULL, 0);
						}
						filter->filter_len = i;
						break;
					}
					case T_UNKNOWN:
						fprintf(stderr, "WARN : Unknown filter setting: %s\n", token2);
					} // switch (data_type)
				}
			}
		}
	}
OUT:
	FREE(f);
	return ret;
}

void filter_dump(struct filter *filter, char *buffer, unsigned int buf_len) {
	unsigned int i, pos = 0;
	memset(buffer, 0, buf_len);
	pos += snprintf(buffer + pos, buf_len - pos, "Action: %s",
		filter->action == FILTER_ACCEPT_ALL ? "ACCEPT_ALL (default)" :
		filter->action == FILTER_REJECT_ALL ? "REJECT_ALL (default)" :
		filter->action == FILTER_ACCEPT     ? "ACCEPT" :
		filter->action == FILTER_REJECT     ? "REJECT" : "???");
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT)
		pos += snprintf(buffer + pos, buf_len - pos, " Name: %-20s", filter->name);
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT) {
		char tmp_data[MAX_FILTER_LEN * 6], tmp_mask[MAX_FILTER_LEN * 6];
		ts_hex_dump_buf(tmp_data, sizeof(tmp_data), filter->data, filter->filter_len, 0);
		switch (filter->type) {
		case FILTER_TYPE_DATA:
			pos += snprintf(buffer + pos, buf_len - pos, " Offset: %2d Data: %s", filter->offset, tmp_data);
			break;
		case FILTER_TYPE_MASK:
			ts_hex_dump_buf(tmp_mask, sizeof(tmp_mask), filter->mask, filter->filter_len, 0);
			pos += snprintf(buffer + pos, buf_len - pos, " Match: %s Mask: %s", tmp_data, tmp_mask);
			break;
		case FILTER_TYPE_LENGTH:
			pos += snprintf(buffer + pos, buf_len - pos, " Length:");
			for (i = 0; i < filter->filter_len; i++)
				pos += snprintf(buffer + pos, buf_len - pos, " 0x%02x", filter->data[i]);
			break;
		} // switch (filter->type)
	}
}

static enum filter_action filter_match(uint8_t *data, unsigned int data_len, struct filter *filter) {
	int i;
	if (filter->action == FILTER_ACCEPT_ALL || filter->action == FILTER_REJECT_ALL)
		return filter->action;
	if (filter->action == FILTER_ACCEPT || filter->action == FILTER_REJECT) {
		switch (filter->type) {
		case FILTER_TYPE_DATA: {
			if (filter->filter_len + filter->offset > data_len)
				return FILTER_NO_MATCH;
			if (memcmp(data + filter->offset, filter->data, filter->filter_len) == 0)
				return filter->action;
			break;
		}
		case FILTER_TYPE_MASK: {
			if ((unsigned int)filter->filter_len + 3 > data_len)
				return FILTER_NO_MATCH;
			int matched = 0;
			// Check data[0] against filter->data[0]
			if ((data[0] & filter->mask[0]) == (filter->data[0] & filter->mask[0])) {
				matched++;
				for (i = 1; i < filter->filter_len; i++) {
					// Check data[3...] against filter->data[1...]
					if ((data[i + 2] & filter->mask[i]) == (filter->data[i] & filter->mask[i]))
						matched++;
				}
			}
			if (matched == filter->filter_len)
				return filter->action;
			break;
		}
		case FILTER_TYPE_LENGTH: {
			if (data_len < 3)
				return FILTER_NO_MATCH;
			for (i = 0; i < filter->filter_len; i++) {
				// data[2] holds the section length (not quite, but close to what
				// we need, because length= can contain sizes > 255)
				if (data[2] == filter->data[i])
					return filter->action;
			}
		}
		} // switch (filter->type)
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
