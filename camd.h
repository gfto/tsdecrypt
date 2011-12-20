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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#ifndef CAMD_H
#define CAMD_H

#include "data.h"

int						camd_tcp_connect	(struct in_addr ip, int port);

struct camd_msg *		camd_msg_alloc		(enum msg_type msg_type, uint16_t ca_id, uint16_t service_id, uint8_t *data, uint8_t data_len);
void					camd_msg_free   	(struct camd_msg **pmsg);

void					camd_start			(struct ts *ts);
void					camd_stop			(struct ts *ts);

void					camd_process_packet	(struct ts *ts, struct camd_msg *msg);

void					camd_proto_cs378x	(struct camd_ops *ops);
void					camd_proto_newcamd	(struct camd_ops *ops);

#endif
