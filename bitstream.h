/*
 * TS bitstream functions
 * The following functions are copied from bitstream/mpeg.ts and bitstream/mpeg/pes.h

 * Copyright (c) 2010-2011 VideoLAN

 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:

 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef BITSTREAM_H
#define BITSTREAM_H

#include <stdbool.h>
#include <inttypes.h>

#define TS_SIZE                     188
#define TS_HEADER_SIZE              4
#define PES_HEADER_SIZE_PTS         14
#define PES_HEADER_SIZE_PTSDTS      19
#define PES_STREAM_ID_MIN           0xbc
#define PES_STREAM_ID_PRIVATE_2     0xbf

static inline bool ts_validate(const uint8_t *p_ts)
{
    return p_ts[0] == 0x47;
}

static inline bool ts_get_unitstart(const uint8_t *p_ts)
{
    return !!(p_ts[1] & 0x40);
}

static inline bool ts_has_payload(const uint8_t *p_ts)
{
    return !!(p_ts[3] & 0x10);
}

static inline bool ts_has_adaptation(const uint8_t *p_ts)
{
    return !!(p_ts[3] & 0x20);
}

static inline uint8_t ts_get_adaptation(const uint8_t *p_ts)
{
    return p_ts[4];
}

static inline uint8_t pes_get_streamid(const uint8_t *p_pes)
{
    return p_pes[3];
}

static inline bool pes_validate(const uint8_t *p_pes)
{
    return (p_pes[0] == 0x0 && p_pes[1] == 0x0 && p_pes[2] == 0x1
             && p_pes[3] >= PES_STREAM_ID_MIN);
}

static inline bool pes_validate_header(const uint8_t *p_pes)
{
    return ((p_pes[6] & 0xc0) == 0x80);
}

static inline bool pes_has_pts(const uint8_t *p_pes)
{
    return !!(p_pes[7] & 0x80);
}

static inline bool pes_has_dts(const uint8_t *p_pes)
{
    return (p_pes[7] & 0xc0) == 0xc0;
}

static inline bool pes_validate_pts(const uint8_t *p_pes)
{
    return ((p_pes[9] & 0xe1) == 0x21)
            && (p_pes[11] & 0x1) && (p_pes[13] & 0x1);
}

static inline bool pes_validate_dts(const uint8_t *p_pes)
{
    return (p_pes[9] & 0x10) && ((p_pes[14] & 0xf1) == 0x11)
            && (p_pes[16] & 0x1) && (p_pes[18] & 0x1);
}

#endif
