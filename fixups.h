/*
 * CA system specific fixups
 * Copyright (C) 2010-2012 OSCAM Developers.
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
#ifndef FIXUPS_H
#define FIXUPS_H

#include <inttypes.h>

int viaccess_reassemble_emm(uint8_t *buffer, unsigned int *len);
int cryptoworks_reassemble_emm(uint8_t *buffer, unsigned int *len);

#endif
