/*
 * Utility functions header
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
#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>
#include <arpa/inet.h>

unsigned long crc32(unsigned long crc, const uint8_t *buf, unsigned int len);
int32_t boundary(int32_t exp, int32_t n);
uint8_t *init_4b(uint32_t val, uint8_t *b);
uint8_t *init_4l(uint32_t val, uint8_t *b);
uint8_t *init_2b(uint32_t val, uint8_t *b);
void set_thread_name(char *thread_name);
int decode_hex_string(char *hex, uint8_t *bin, int asc_len);
int64_t get_time(void);
unsigned int file_hex2buf(char *filename, uint8_t *buffer, unsigned int buf_size);
char *my_inet_ntop(int family, struct sockaddr *addr, char *dest, int dest_len);

#endif
