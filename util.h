#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>

unsigned long crc32(unsigned long crc, const uint8_t *buf, unsigned int len);
int32_t boundary(int32_t exp, int32_t n);
uint8_t *init_4b(uint32_t val, uint8_t *b);
uint8_t *init_4l(uint32_t val, uint8_t *b);
uint8_t *init_2b(uint32_t val, uint8_t *b);

#endif
