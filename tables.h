/*
 * Process PSI tables header
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
#ifndef TABLE_H
#define TABLES_H

#include "data.h"

void process_pat(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_cat(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_pmt(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_sdt(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet);

#endif
