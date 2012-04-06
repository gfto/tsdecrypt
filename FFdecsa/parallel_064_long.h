/* FFdecsa -- fast decsa algorithm
 *
 * Copyright (C) 2007 Dark Avenger
 *               2003-2004  fatih89r
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "parallel_std_def.h"

typedef unsigned long long group;
#define GROUP_PARALLELISM 64
#define FF0() 0x0ULL
#define FF1() 0xffffffffffffffffULL

typedef unsigned long long batch;
#define BYTES_PER_BATCH 8
#define B_FFN_ALL_29() 0x2929292929292929ULL
#define B_FFN_ALL_02() 0x0202020202020202ULL
#define B_FFN_ALL_04() 0x0404040404040404ULL
#define B_FFN_ALL_10() 0x1010101010101010ULL
#define B_FFN_ALL_40() 0x4040404040404040ULL
#define B_FFN_ALL_80() 0x8080808080808080ULL

#define M_EMPTY()

#include "fftable.h"
