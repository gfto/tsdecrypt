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


#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include "FFdecsa.h"

#ifndef NULL
#define NULL 0
#endif

#include "FFdecsa_test_testcases.h"

int compare(unsigned char *p1, unsigned char *p2, int n, int silently){
  int i;
  int ok=1;
  for(i=0;i<n;i++){
    if(i==3) continue; // tolerate this
    if(p1[i]!=p2[i]){
//      fprintf(stderr,"at pos 0x%02x, got 0x%02x instead of 0x%02x\n",i,p1[i],p2[i]);
      ok=0;
    }
  }
  if(!silently){
    if(ok){
       fprintf(stderr,"CORRECT!\n");
    }
    else{
       fprintf(stderr,"FAILED!\n");
    }
  }
  return ok;
}


//MAIN

#define TS_PKTS_FOR_TEST 30*1000
//#define TS_PKTS_FOR_TEST 1000*1000
unsigned char megabuf[188*TS_PKTS_FOR_TEST];
unsigned char onebuf[188];

unsigned char *cluster[10];

int main(void){
  int i;
  struct timeval tvs,tve;
  void *keys=get_key_struct();
  int ok=1;

  fprintf(stderr,"FFdecsa 1.0: testing correctness and speed\n");

/* begin correctness testing */

  set_control_words(keys,test_invalid_key,test_1_key);
  memcpy(onebuf,test_1_encrypted,188);
  cluster[0]=onebuf;cluster[1]=onebuf+188;cluster[2]=NULL;
  decrypt_packets(keys,cluster);
  ok*=compare(onebuf,test_1_expected,188,0);

  set_control_words(keys,test_2_key,test_invalid_key);
  memcpy(onebuf,test_2_encrypted,188);
  cluster[0]=onebuf;cluster[1]=onebuf+188;cluster[2]=NULL;
  decrypt_packets(keys,cluster);
  ok*=compare(onebuf,test_2_expected,188,0);

  set_control_words(keys,test_3_key,test_invalid_key);
  memcpy(onebuf,test_3_encrypted,188);
  cluster[0]=onebuf;cluster[1]=onebuf+188;cluster[2]=NULL;
  decrypt_packets(keys,cluster);
  ok*=compare(onebuf,test_3_expected,188,0);

  set_control_words(keys,test_p_10_0_key,test_invalid_key);
  memcpy(onebuf,test_p_10_0_encrypted,188);
  cluster[0]=onebuf;cluster[1]=onebuf+188;cluster[2]=NULL;
  decrypt_packets(keys,cluster);
  ok*=compare(onebuf,test_p_10_0_expected,188,0);

  set_control_words(keys,test_p_1_6_key,test_invalid_key);
  memcpy(onebuf,test_p_1_6_encrypted,188);
  cluster[0]=onebuf;cluster[1]=onebuf+188;cluster[2]=NULL;
  decrypt_packets(keys,cluster);
  ok*=compare(onebuf,test_p_1_6_expected,188,0);

/* begin speed testing */

#if 0
// test on short packets
#define s_encrypted test_p_1_6_encrypted
#define s_key_e     test_p_1_6_key
#define s_key_o     test_invalid_key
#define s_expected  test_p_1_6_expected

#else
//test on full packets
#define s_encrypted test_2_encrypted
#define s_key_e     test_2_key
#define s_key_o     test_invalid_key
#define s_expected  test_2_expected

#endif

  for(i=0;i<TS_PKTS_FOR_TEST;i++){
    memcpy(&megabuf[188*i],s_encrypted,188);
  }
// test that packets are not shuffled around
// so, let's put an undecryptable packet somewhere in the middle (we will use a wrong key)
#define noONE_POISONED_PACKET
#ifdef ONE_POISONED_PACKET
  memcpy(&megabuf[188*(TS_PKTS_FOR_TEST*2/3)],test_3_encrypted,188);
#endif

  // start decryption
  set_control_words(keys,s_key_e,s_key_o);
  gettimeofday(&tvs,NULL);
#if 0
// force one by one
  for(i=0;i<TS_PKTS_FOR_TEST;i++){
    cluster[0]=megabuf+188*i;cluster[1]=onebuf+188*i+188;cluster[2]=NULL;
    decrypt_packets(keys,cluster);
  }
#else
  {
    int done=0;
    while(done<TS_PKTS_FOR_TEST){
      //fprintf(stderr,"done=%i\n",done);
      cluster[0]=megabuf+188*done;cluster[1]=megabuf+188*TS_PKTS_FOR_TEST;cluster[2]=NULL;
      done+=decrypt_packets(keys,cluster);
    }
  }
#endif
  gettimeofday(&tve,NULL);
  //end decryption

  fprintf(stderr,"speed=%f Mbit/s\n",(184*TS_PKTS_FOR_TEST*8)/((tve.tv_sec-tvs.tv_sec)+1e-6*(tve.tv_usec-tvs.tv_usec))/1000000);
  fprintf(stderr,"speed=%f pkts/s\n",TS_PKTS_FOR_TEST/((tve.tv_sec-tvs.tv_sec)+1e-6*(tve.tv_usec-tvs.tv_usec)));

  // this packet couldn't be decrypted correctly
#ifdef ONE_POISONED_PACKET
  compare(megabuf+188*(TS_PKTS_FOR_TEST*2/3),test_3_expected,188,0); /* will fail because we used a wrong key */
#endif
  // these should be ok
  ok*=compare(megabuf,s_expected,188,0);
  ok*=compare(megabuf+188*511,s_expected,188,0);
  ok*=compare(megabuf+188*512,s_expected,188,0);
  ok*=compare(megabuf+188*319,s_expected,188,0);
  ok*=compare(megabuf+188*(TS_PKTS_FOR_TEST-1),s_expected,188,0);

  for(i=0;i<TS_PKTS_FOR_TEST;i++){
    if(!compare(megabuf+188*i,s_expected,188,1)){
      fprintf(stderr,"FAILED COMPARISON OF PACKET %10i\n",i);
      ok=0;
    };
  }

  return ok ? 0 : 10;
}
