/* FFdecsa -- fast decsa algorithm
 *
 * Copyright (C) 2003-2004  fatih89r
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


struct group_t{
  unsigned long long int s1;
  unsigned long long int s2;
};
typedef struct group_t group;

#define GROUP_PARALLELISM 128

group static inline FF0(){
  group res;
  res.s1=0x0ULL;
  res.s2=0x0ULL;
  return res;
}

group static inline FF1(){
  group res;
  res.s1=0xffffffffffffffffULL;
  res.s2=0xffffffffffffffffULL;
  return res;
}

group static inline FFAND(group a,group b){
  group res;
  res.s1=a.s1&b.s1;
  res.s2=a.s2&b.s2;
  return res;
}

group static inline FFOR(group a,group b){
  group res;
  res.s1=a.s1|b.s1;
  res.s2=a.s2|b.s2;
  return res;
}

group static inline FFXOR(group a,group b){
  group res;
  res.s1=a.s1^b.s1;
  res.s2=a.s2^b.s2;
  return res;
}

group static inline FFNOT(group a){
  group res;
  res.s1=~a.s1;
  res.s2=~a.s2;
  return res;
}


/* 64 rows of 128 bits */

void static inline FFTABLEIN(unsigned char *tab, int g, unsigned char *data){
  *(((int *)tab)+2*g)=*((int *)data);
  *(((int *)tab)+2*g+1)=*(((int *)data)+1);
}

void static inline FFTABLEOUT(unsigned char *data, unsigned char *tab, int g){
  *((int *)data)=*(((int *)tab)+2*g);
  *(((int *)data)+1)=*(((int *)tab)+2*g+1);
}

void static inline FFTABLEOUTXORNBY(int n, unsigned char *data, unsigned char *tab, int g){
  int j;
  for(j=0;j<n;j++){
    *(data+j)^=*(tab+8*g+j);
  }
}


struct batch_t{
  unsigned long long int s1;
  unsigned long long int s2;
};
typedef struct batch_t batch;

#define BYTES_PER_BATCH 16

batch static inline B_FFAND(batch a,batch b){
  batch res;
  res.s1=a.s1&b.s1;
  res.s2=a.s2&b.s2;
  return res;
}

batch static inline B_FFOR(batch a,batch b){
  batch res;
  res.s1=a.s1|b.s1;
  res.s2=a.s2|b.s2;
  return res;
}

batch static inline B_FFXOR(batch a,batch b){
  batch res;
  res.s1=a.s1^b.s1;
  res.s2=a.s2^b.s2;
  return res;
}


batch static inline B_FFN_ALL_29(){
  batch res;
  res.s1=0x2929292929292929ULL;
  res.s2=0x2929292929292929ULL;
  return res;
}

batch static inline B_FFN_ALL_02(){
  batch res;
  res.s1=0x0202020202020202ULL;
  res.s2=0x0202020202020202ULL;
  return res;
}
batch static inline B_FFN_ALL_04(){
  batch res;
  res.s1=0x0404040404040404ULL;
  res.s2=0x0404040404040404ULL;
  return res;
}
batch static inline B_FFN_ALL_10(){
  batch res;
  res.s1=0x1010101010101010ULL;
  res.s2=0x1010101010101010ULL;
  return res;
}
batch static inline B_FFN_ALL_40(){
  batch res;
  res.s1=0x4040404040404040ULL;
  res.s2=0x4040404040404040ULL;
  return res;
}
batch static inline B_FFN_ALL_80(){
  batch res;
  res.s1=0x8080808080808080ULL;
  res.s2=0x8080808080808080ULL;
  return res;
}
batch static inline B_FFSH8L(batch a,int n){
  batch res;
  res.s1=a.s1<<n;
  res.s2=a.s2<<n;
  return res;
}

batch static inline B_FFSH8R(batch a,int n){
  batch res;
  res.s1=a.s1>>n;
  res.s2=a.s2>>n;
  return res;
}


void static inline M_EMPTY(void){
}
