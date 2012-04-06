##### compiling with g++ gives a little more speed
#COMPILER=gcc
#COMPILER=g++

###there are two functions which apparently don't want to be inlined
#FLAGS=-O3 -march=athlon-xp -fexpensive-optimizations -funroll-loops -finline-limit=6000000 --param max-unrolled-insns=500
#FLAGS=-O3 -march=athlon-xp -fexpensive-optimizations -funroll-loops --param max-unrolled-insns=500
#FLAGS=-O3 -march=pentium3 -fexpensive-optimizations -funroll-loops

###icc crashes for unknown reasons
#COMPILER=/opt/intel_cc_80/bin/icc
#FLAGS=-O3 -march=pentiumiii

#FLAGS += -g
#FLAGS += -fno-alias
#FLAGS += -vec_report3
#FLAGS += -Wall -Winline
#FLAGS += -fomit-frame-pointer 
#FLAGS += -pg

COMPILER ?= g++
FLAGS    ?= -Wall -fPIC -O3 -march=pentium -mmmx -fomit-frame-pointer -fexpensive-optimizations -funroll-loops

H_FILES = FFdecsa.h parallel_generic.h parallel_std_def.h fftable.h \
          parallel_032_4char.h \
          parallel_032_int.h \
          parallel_064_2int.h \
          parallel_064_8charA.h \
          parallel_064_8char.h \
          parallel_064_long.h \
          parallel_064_mmx.h \
          parallel_128_16charA.h \
          parallel_128_16char.h \
          parallel_128_2long.h \
          parallel_128_2mmx.h \
          parallel_128_4int.h \
          parallel_128_sse2.h \
          parallel_128_sse.h

all: FFdecsa.o FFdecsa_test.done

%.o: %.c
	$(COMPILER) $(FLAGS) -DPARALLEL_MODE=$(PARALLEL_MODE) -c $<

FFdecsa_test:	FFdecsa_test.o FFdecsa.o
	$(COMPILER) $(FLAGS) -o FFdecsa_test FFdecsa_test.o FFdecsa.o

FFdecsa_test.o: FFdecsa_test.c FFdecsa.h FFdecsa_test_testcases.h
FFdecsa.o: 	FFdecsa.c stream.c $(H_FILES)

FFdecsa_test.done: FFdecsa_test
	@./FFdecsa_test
	@touch FFdecsa_test.done

clean:
	@rm -f FFdecsa_test FFdecsa_test.done FFdecsa_test.o FFdecsa.o

test:	FFdecsa_test
	sync;usleep 200000;nice --19 ./FFdecsa_test
