/*
 * CAMD communications header
 * Copyright (C) 2011 Unix Solutions Ltd.
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
#ifndef CAMD_H
#define CAMD_H

#include "data.h"

int connect_client							(int socktype, const char *hostname, const char *service);

struct camd_msg *		camd_msg_alloc		(enum msg_type msg_type, uint16_t ca_id, uint16_t service_id, uint8_t *data, int data_len);
void					camd_msg_free   	(struct camd_msg **pmsg);

void					camd_set_cw			(struct ts *ts, uint8_t *new_cw, int check_validity);

void					camd_start			(struct ts *ts);
void					camd_stop			(struct ts *ts);

void					camd_process_packet	(struct ts *ts, struct camd_msg *msg);

void					camd_proto_cs378x	(struct camd_ops *ops);
void					camd_proto_newcamd	(struct camd_ops *ops);

#endif
