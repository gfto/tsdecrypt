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
  unsigned char s1[8];
};
typedef struct group_t group;

#define GROUP_PARALLELISM 64

group static inline FF0(){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x0;
  return res;
}

group static inline FF1(){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0xff;
  return res;
}

group static inline FFAND(group a,group b){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]&b.s1[i];
  return res;
}

group static inline FFOR(group a,group b){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]|b.s1[i];
  return res;
}

group static inline FFXOR(group a,group b){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]^b.s1[i];
  return res;
}

group static inline FFNOT(group a){
  group res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=~a.s1[i];
  return res;
}


/* 64 rows of 64 bits */

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
  unsigned char s1[8];
};
typedef struct batch_t batch;

#define BYTES_PER_BATCH 8

batch static inline B_FFAND(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]&b.s1[i];
  return res;
}

batch static inline B_FFOR(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]|b.s1[i];
  return res;
}

batch static inline B_FFXOR(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]^b.s1[i];
  return res;
}


batch static inline B_FFN_ALL_29(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x29;
  return res;
}
batch static inline B_FFN_ALL_02(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x02;
  return res;
}
batch static inline B_FFN_ALL_04(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x04;
  return res;
}
batch static inline B_FFN_ALL_10(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x10;
  return res;
}
batch static inline B_FFN_ALL_40(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x40;
  return res;
}
batch static inline B_FFN_ALL_80(){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=0x80;
  return res;
}

batch static inline B_FFSH8L(batch a,int n){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]<<n;
  return res;
}

batch static inline B_FFSH8R(batch a,int n){
  batch res;
  int i;
  for(i=0;i<8;i++) res.s1[i]=a.s1[i]>>n;
  return res;
}

void static inline M_EMPTY(void){
}
