/* logic -- synthetize logic functions with 4 inputs
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




/* Can we use negated inputs? */
#define noNEGATEDTOO


#include <stdio.h>


/*
 * abcd
 */

#define BINARY(b15,b14,b13,b12,b11,b10,b9,b8,b7,b6,b5,b4,b3,b2,b1,b0) \
  ((b15)<<15)|((b14)<<14)|((b13)<<13)|((b12)<<12)| \
  ((b11)<<11)|((b10)<<10)|((b9) << 9)|((b8) << 8)| \
  ((b7) << 7)|((b6) << 6)|((b5) << 5)|((b4) << 4)| \
  ((b3) << 3)|((b2) << 2)|((b1) << 1)|((b0) << 0)

struct fun{
  int level;
  int op_type;
  int op1;
  int op2;
};

struct fun db[65536];
int n_fun;

#define LEVEL_ALOT 1000000

#define OP_FALSE 0
#define OP_TRUE  1
#define OP_SRC   2
#define OP_AND   3
#define OP_OR    4
#define OP_XOR   5

#define SRC_A 10
#define SRC_B 20
#define SRC_C 30
#define SRC_D 40
#define SRC_AN 11
#define SRC_BN 21
#define SRC_CN 31
#define SRC_DN 41

void dump_element_prefix(int);
void dump_element_infix(int);

int main(void){
  int i,j;
  int l,p1,p2;
  int candidate;
  int max_p2_lev;
  
  for(i=0;i<65536;i++){
    db[i].level=LEVEL_ALOT;
  }
  n_fun=0;

  db[0].level=0;
  db[0].op_type=OP_FALSE;
  n_fun++;

  db[65535].level=0;
  db[65535].op_type=OP_TRUE;
  n_fun++;

  db[BINARY(0,0,0,0, 0,0,0,0,  1,1,1,1, 1,1,1,1)].level=0;
  db[BINARY(0,0,0,0, 0,0,0,0,  1,1,1,1, 1,1,1,1)].op_type=OP_SRC;
  db[BINARY(0,0,0,0, 0,0,0,0,  1,1,1,1, 1,1,1,1)].op1=SRC_A;
  n_fun++;

  db[BINARY(0,0,0,0, 1,1,1,1,  0,0,0,0, 1,1,1,1)].level=0;
  db[BINARY(0,0,0,0, 1,1,1,1,  0,0,0,0, 1,1,1,1)].op_type=OP_SRC;
  db[BINARY(0,0,0,0, 1,1,1,1,  0,0,0,0, 1,1,1,1)].op1=SRC_B;
  n_fun++;

  db[BINARY(0,0,1,1, 0,0,1,1,  0,0,1,1, 0,0,1,1)].level=0;
  db[BINARY(0,0,1,1, 0,0,1,1,  0,0,1,1, 0,0,1,1)].op_type=OP_SRC;
  db[BINARY(0,0,1,1, 0,0,1,1,  0,0,1,1, 0,0,1,1)].op1=SRC_C;
  n_fun++;

  db[BINARY(0,1,0,1, 0,1,0,1,  0,1,0,1, 0,1,0,1)].level=0;
  db[BINARY(0,1,0,1, 0,1,0,1,  0,1,0,1, 0,1,0,1)].op_type=OP_SRC;
  db[BINARY(0,1,0,1, 0,1,0,1,  0,1,0,1, 0,1,0,1)].op1=SRC_D;
  n_fun++;
#ifdef NEGATEDTOO
  db[BINARY(1,1,1,1, 1,1,1,1,  0,0,0,0, 0,0,0,0)].level=0;
  db[BINARY(1,1,1,1, 1,1,1,1,  0,0,0,0, 0,0,0,0)].op_type=OP_SRC;
  db[BINARY(1,1,1,1, 1,1,1,1,  0,0,0,0, 0,0,0,0)].op1=SRC_AN;
  n_fun++;

  db[BINARY(1,1,1,1, 0,0,0,0,  1,1,1,1, 0,0,0,0)].level=0;
  db[BINARY(1,1,1,1, 0,0,0,0,  1,1,1,1, 0,0,0,0)].op_type=OP_SRC;
  db[BINARY(1,1,1,1, 0,0,0,0,  1,1,1,1, 0,0,0,0)].op1=SRC_BN;
  n_fun++;

  db[BINARY(1,1,0,0, 1,1,0,0,  1,1,0,0, 1,1,0,0)].level=0;
  db[BINARY(1,1,0,0, 1,1,0,0,  1,1,0,0, 1,1,0,0)].op_type=OP_SRC;
  db[BINARY(1,1,0,0, 1,1,0,0,  1,1,0,0, 1,1,0,0)].op1=SRC_CN;
  n_fun++;

  db[BINARY(1,0,1,0, 1,0,1,0,  1,0,1,0, 1,0,1,0)].level=0;
  db[BINARY(1,0,1,0, 1,0,1,0,  1,0,1,0, 1,0,1,0)].op_type=OP_SRC;
  db[BINARY(1,0,1,0, 1,0,1,0,  1,0,1,0, 1,0,1,0)].op1=SRC_DN;
  n_fun++;
#endif

  for(l=0;l<100;l++){
    printf("calculating level %i\n",l);
    for(p1=1;p1<65536;p1++){
      if(db[p1].level==LEVEL_ALOT) continue;
      max_p2_lev=l-db[p1].level-1;
      for(p2=p1+1;p2<65536;p2++){
        if(db[p2].level>max_p2_lev) continue;

        candidate=p1&p2;
        if(db[candidate].level==LEVEL_ALOT){
          //found new
          db[candidate].level=db[p1].level+db[p2].level+1;
          db[candidate].op_type=OP_AND;
          db[candidate].op1=p1;
          db[candidate].op2=p2;
          n_fun++;
	}

        candidate=p1|p2;
        if(db[candidate].level==LEVEL_ALOT){
          //found new
          db[candidate].level=db[p1].level+db[p2].level+1;
          db[candidate].op_type=OP_OR;
          db[candidate].op1=p1;
          db[candidate].op2=p2;
          n_fun++;
	}

        candidate=p1^p2;
        if(db[candidate].level==LEVEL_ALOT){
          //found new
          db[candidate].level=db[p1].level+db[p2].level+1;
          db[candidate].op_type=OP_XOR;
          db[candidate].op1=p1;
          db[candidate].op2=p2;
          n_fun++;
	}

      }
    }
    printf("num fun=%i\n\n",n_fun);
    fflush(stdout);
    if(n_fun>=65536) break;
  }


  for(i=0;i<65536;i++){
    if(db[i].level==LEVEL_ALOT) continue;

    printf("PREFIX ");
    for(j=15;j>=0;j--){
      printf("%i",i&(1<<j)?1:0);
      if(j%4==0) printf(" ");
      if(j%8==0) printf(" ");
    }
    printf(" : lev %2i: ",db[i].level);
    dump_element_prefix(i);
    printf("\n");

    printf("INFIX  ");
    for(j=15;j>=0;j--){
      printf("%i",i&(1<<j)?1:0);
      if(j%4==0) printf(" ");
      if(j%8==0) printf(" ");
    }
    printf(" : lev %2i: ",db[i].level);
    dump_element_infix(i);
    printf("\n");
  }
  
  return 0;
}

void dump_element_prefix(int e){
  if(db[e].level==LEVEL_ALOT){
    printf("PANIC!\n");
    return;
  };
  switch(db[e].op_type){
  case OP_FALSE:
    printf("0");
    break;
  case OP_TRUE:
    printf("1");
    break;
  case OP_SRC:
    switch(db[e].op1){
    case SRC_A:
      printf("a");
      break;
    case SRC_B:
      printf("b");
      break;
    case SRC_C:
      printf("c");
      break;
    case SRC_D:
      printf("d");
      break;
    case SRC_AN:
      printf("an");
      break;
    case SRC_BN:
      printf("bn");
      break;
    case SRC_CN:
      printf("cn");
      break;
    case SRC_DN:
      printf("dn");
      break;
    }
    break;
  case OP_AND:
    printf("FFAND(");
    dump_element_prefix(db[e].op1);
    printf(",");
    dump_element_prefix(db[e].op2);
    printf(")");
    break;
  case OP_OR:
    printf("FFOR(");
    dump_element_prefix(db[e].op1);
    printf(",");
    dump_element_prefix(db[e].op2);
    printf(")");
    break;
  case OP_XOR:
    printf("FFXOR(");
    dump_element_prefix(db[e].op1);
    printf(",");
    dump_element_prefix(db[e].op2);
    printf(")");
    break;
  }
}

void dump_element_infix(int e){
  if(db[e].level==LEVEL_ALOT){
    printf("PANIC!\n");
    return;
  };
  switch(db[e].op_type){
  case OP_FALSE:
    printf("0");
    break;
  case OP_TRUE:
    printf("1");
    break;
  case OP_SRC:
    switch(db[e].op1){
    case SRC_A:
      printf("a");
      break;
    case SRC_B:
      printf("b");
      break;
    case SRC_C:
      printf("c");
      break;
    case SRC_D:
      printf("d");
      break;
    case SRC_AN:
      printf("an");
      break;
    case SRC_BN:
      printf("bn");
      break;
    case SRC_CN:
      printf("cn");
      break;
    case SRC_DN:
      printf("dn");
      break;
    }
    break;
  case OP_AND:
    printf("( ");
    dump_element_infix(db[e].op1);
    printf("&");
    dump_element_infix(db[e].op2);
    printf(" )");
    break;
  case OP_OR:
    printf("( ");
    dump_element_infix(db[e].op1);
    printf("|");
    dump_element_infix(db[e].op2);
    printf(" )");
    break;
  case OP_XOR:
    printf("( ");
    dump_element_infix(db[e].op1);
    printf("^");
    dump_element_infix(db[e].op2);
    printf(" )");
    break;
  }
}
