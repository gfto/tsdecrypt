/*
 * Exec external program to notify for an event
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
#ifndef NOTIFY_H
# define NOTIFY_H

#include "libfuncs/queue.h"
#include "data.h"

struct notify *notify_alloc(struct ts *ts);

__attribute__ ((format(printf, 3, 4)))
void notify(struct ts *ts, char *msg_id, char *text_fmt, ...);

__attribute__ ((format(printf, 3, 4)))
void notify_sync(struct ts *ts, char *msg_id, char *text_fmt, ...);

void notify_free(struct notify **pn);

#endif
