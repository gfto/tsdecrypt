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
#ifndef FILTERS_H
#define FILTERS_H

#include <inttypes.h>

#include "data.h"

int filter_parse(char *filter_def, struct filter *filter);

int filter_match_emm(struct ts *ts, uint8_t *data, unsigned int data_len);

void filter_dump(struct filter *filter, char *buffer, unsigned int buf_len);

#endif
