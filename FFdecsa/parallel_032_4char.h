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
  unsigned char s1,s2,s3,s4;
};
typedef struct group_t group;

#define GROUP_PARALLELISM 32

group static inline FF0(){
  group res;
  res.s1=0x0;
  res.s2=0x0;
  res.s3=0x0;
  res.s4=0x0;
  return res;
}

group static inline FF1(){
  group res;
  res.s1=0xff;
  res.s2=0xff;
  res.s3=0xff;
  res.s4=0xff;
  return res;
}

group static inline FFAND(group a,group b){
  group res;
  res.s1=a.s1&b.s1;
  res.s2=a.s2&b.s2;
  res.s3=a.s3&b.s3;
  res.s4=a.s4&b.s4;
  return res;
}

group static inline FFOR(group a,group b){
  group res;
  res.s1=a.s1|b.s1;
  res.s2=a.s2|b.s2;
  res.s3=a.s3|b.s3;
  res.s4=a.s4|b.s4;
  return res;
}

group static inline FFXOR(group a,group b){
  group res;
  res.s1=a.s1^b.s1;
  res.s2=a.s2^b.s2;
  res.s3=a.s3^b.s3;
  res.s4=a.s4^b.s4;
  return res;
}

group static inline FFNOT(group a){
  group res;
  res.s1=~a.s1;
  res.s2=~a.s2;
  res.s3=~a.s3;
  res.s4=~a.s4;
  return res;
}


/* 64 rows of 32 bits */

void static inline FFTABLEIN(unsigned char *tab, int g, unsigned char *data){
  *(((int *)tab)+g)=*((int *)data);
  *(((int *)tab)+32+g)=*(((int *)data)+1);
}

void static inline FFTABLEOUT(unsigned char *data, unsigned char *tab, int g){
  *((int *)data)=*(((int *)tab)+g);
  *(((int *)data)+1)=*(((int *)tab)+32+g);
}

void static inline FFTABLEOUTXORNBY(int n, unsigned char *data, unsigned char *tab, int g){
  int j;
  for(j=0;j<n;j++){
    *(data+j)^=*(tab+4*(g+(j>=4?32-1:0))+j);
  }
}

struct batch_t{
  unsigned char s1,s2,s3,s4;
};
typedef struct batch_t batch;

#define BYTES_PER_BATCH 4

batch static inline B_FFAND(batch a,batch b){
  batch res;
  res.s1=a.s1&b.s1;
  res.s2=a.s2&b.s2;
  res.s3=a.s3&b.s3;
  res.s4=a.s4&b.s4;
  return res;
}

batch static inline B_FFOR(batch a,batch b){
  batch res;
  res.s1=a.s1|b.s1;
  res.s2=a.s2|b.s2;
  res.s3=a.s3|b.s3;
  res.s4=a.s4|b.s4;
  return res;
}

batch static inline B_FFXOR(batch a,batch b){
  batch res;
  res.s1=a.s1^b.s1;
  res.s2=a.s2^b.s2;
  res.s3=a.s3^b.s3;
  res.s4=a.s4^b.s4;
  return res;
}


batch static inline B_FFN_ALL_29(){
  batch res;
  res.s1=0x29;
  res.s2=0x29;
  res.s3=0x29;
  res.s4=0x29;
  return res;
}
batch static inline B_FFN_ALL_02(){
  batch res;
  res.s1=0x02;
  res.s2=0x02;
  res.s3=0x02;
  res.s4=0x02;
  return res;
}
batch static inline B_FFN_ALL_04(){
  batch res;
  res.s1=0x04;
  res.s2=0x04;
  res.s3=0x04;
  res.s4=0x04;
  return res;
}
batch static inline B_FFN_ALL_10(){
  batch res;
  res.s1=0x10;
  res.s2=0x10;
  res.s3=0x10;
  res.s4=0x10;
  return res;
}
batch static inline B_FFN_ALL_40(){
  batch res;
  res.s1=0x40;
  res.s2=0x40;
  res.s3=0x40;
  res.s4=0x40;
  return res;
}
batch static inline B_FFN_ALL_80(){
  batch res;
  res.s1=0x80;
  res.s2=0x80;
  res.s3=0x80;
  res.s4=0x80;
  return res;
}

batch static inline B_FFSH8L(batch a,int n){
  batch res;
  res.s1=a.s1<<n;
  res.s2=a.s2<<n;
  res.s3=a.s3<<n;
  res.s4=a.s4<<n;
  return res;
}

batch static inline B_FFSH8R(batch a,int n){
  batch res;
  res.s1=a.s1>>n;
  res.s2=a.s2>>n;
  res.s3=a.s3>>n;
  res.s4=a.s4>>n;
  return res;
}


void static inline M_EMPTY(void){
}
