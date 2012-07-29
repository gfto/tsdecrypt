/*
 * Process packets header
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
#ifndef PROCESS_H
#define PROCESS_H

void *decode_thread(void *_ts);
void *write_thread(void *_ts);
void process_packets(struct ts *ts, uint8_t *data, ssize_t data_len);
void show_pid_report(struct ts *ts);

#endif
