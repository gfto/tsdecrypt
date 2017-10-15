CC = cc
STRIP = strip
CROSS := $(TARGET)
MKDEP = $(CROSS)$(CC) -MP -MM -o $*.d $<
RM = rm -f
MV = mv -f

VERSION = $(shell cat RELEASE)
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
ifeq "$(GIT_VER)" ""
GIT_VER = "release"
endif

ifndef V
Q = @
endif

CFLAGS ?= -O2 -ggdb -pipe -ffunction-sections -fdata-sections \
 -W -Wall -Wextra \
 -Wshadow -Wformat-security -Wstrict-prototypes \
 -Wredundant-decls -Wold-style-definition

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

LDFLAGS ?= -Wl,--gc-sections

ifeq ($(uname_S),Darwin)
LDFLAGS :=
CC := cc -I/opt/local/include
endif

DEFS = -DVERSION=\"$(VERSION)\" -DGIT_VER=\"$(GIT_VER)\"
DEFS += -D_FILE_OFFSET_BITS=64

PREFIX ?= /usr/local

INSTALL_PRG = tsdecrypt
INSTALL_PRG_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)

INSTALL_DOC = tsdecrypt.1
INSTALL_DOC_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/share/man/man1)

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libtsfuncs
TS_LIB = $(TS_DIR)/libtsfuncs.a

tsdecrypt_SRC = data.c \
 csa.c \
 udp.c \
 util.c \
 filter.c \
 camd.c \
 camd-cs378x.c \
 camd-newcamd.c \
 process.c \
 tables.c \
 notify.c \
 tsdecrypt.c
tsdecrypt_LIBS = -lcrypto -lpthread

# If the file do not exist, libdvbcsa will be used
-include FFdecsa.opts

tsdecrypt_OBJS = $(FFDECSA_OBJ) $(FUNCS_LIB) $(TS_LIB) $(tsdecrypt_SRC:.c=.o)

ifeq "$(shell uname -s)" "Linux"
tsdecrypt_LIBS += -lcrypt -lrt
endif

ifeq "$(DECRYPT_LIB)" "ffdecsa"
DEFS += -DDLIB=\"FFdecsa_$(FFDECSA_MODE)\"
DEFS += -DUSE_FFDECSA=1
else
DEFS += -DDLIB=\"libdvbcsa\"
DEFS += -DUSE_LIBDVBCSA=1
tsdecrypt_LIBS += -ldvbcsa
endif

CLEAN_OBJS = $(FFDECSA_OBJ) tsdecrypt $(tsdecrypt_SRC:.c=.o) $(tsdecrypt_SRC:.c=.d)

PROGS = tsdecrypt

.PHONY: ffdecsa dvbcsa help distclean clean install uninstall

all: ffdecsa

ffdecsa: clean
	$(Q)echo "Using FFdecsa as decryption library"
	@-if test -e FFdecsa.opts.saved; then $(MV) FFdecsa.opts.saved FFdecsa.opts; fi
	@-if ! test -e FFdecsa.opts; then ./FFdecsa_init "$(CROSS)" "$(CC)"; fi
	$(Q)$(MAKE) -s tsdecrypt

ffdecsa_force:
	$(Q)$(RM) FFdecsa.opts
	$(Q)$(MAKE) -s ffdecsa

dvbcsa: clean
	$(Q)echo "Using libdvbcsa as decryption library"
	@-if test -f FFdecsa.opts; then $(MV) FFdecsa.opts FFdecsa.opts.saved; fi
	$(Q)$(MAKE) -s tsdecrypt

$(FUNCS_LIB): $(FUNCS_DIR)/libfuncs.h
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

$(TS_LIB): $(TS_DIR)/tsfuncs.h $(TS_DIR)/tsdata.h
	$(Q)echo "  MAKE	$(TS_LIB)"
	$(Q)$(MAKE) -s -C $(TS_DIR)

tsdecrypt: $(tsdecrypt_OBJS)
	$(Q)echo "  LINK	tsdecrypt"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(LDFLAGS) $(DEFS) $(tsdecrypt_OBJS) $(tsdecrypt_LIBS) -o tsdecrypt

%.o: %.c RELEASE
	@$(MKDEP)
	$(Q)echo "  CC	tsdecrypt	$<"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(DEFS) -c $<

FFdecsa/FFdecsa.o:
	$(Q)echo "  MAKE	FFdecsa"
	$(Q)$(MAKE) -s -C FFdecsa FLAGS=$(FFDECSA_FLAGS) PARALLEL_MODE=$(FFDECSA_MODE) COMPILER=$(CROSS)$(CC) FFdecsa.o

-include $(tsdecrypt_SRC:.c=.d)

strip:
	$(Q)echo "  STRIP	$(PROGS)"
	$(Q)$(CROSS)$(STRIP) $(PROGS)

clean:
	$(Q)echo "  RM	$(CLEAN_OBJS)"
	$(Q)$(RM) $(CLEAN_OBJS)

distclean: clean
	$(Q)$(MAKE) -s -C $(TS_DIR) clean
	$(Q)$(MAKE) -s -C $(FUNCS_DIR) clean
	$(Q)$(RM) FFdecsa.opts

install: all
	@install -d "$(INSTALL_PRG_DIR)"
	@install -d "$(INSTALL_DOC_DIR)"
	@echo "INSTALL $(INSTALL_PRG) -> $(INSTALL_PRG_DIR)"
	$(Q)-install $(INSTALL_PRG) "$(INSTALL_PRG_DIR)"
	@echo "INSTALL $(INSTALL_DOC) -> $(INSTALL_DOC_DIR)"
	$(Q)-install --mode 0644 $(INSTALL_DOC) "$(INSTALL_DOC_DIR)"

uninstall:
	@-for FILE in $(INSTALL_PRG); do \
		echo "RM       $(INSTALL_PRG_DIR)/$$FILE"; \
		rm "$(INSTALL_PRG_DIR)/$$FILE"; \
	done
	@-for FILE in $(INSTALL_DOC); do \
		echo "RM       $(INSTALL_DOC_DIR)/$$FILE"; \
		rm "$(INSTALL_DOC_DIR)/$$FILE"; \
	done

help:
	$(Q)echo -e "\
tsdecrypt $(VERSION) ($(GIT_VER)) build\n\n\
Build targets:\n\
  tsdecrypt|all   - Build tsdecrypt with whatever decryption library was chosen\n\
\n\
  dvbcsa          - Build tsdecrypt with libdvbcsa [default]\n\
  ffdecsa         - Build tsdecrypt with shipped FFdecsa.\n\
\n\
  install         - Install tsdecrypt in PREFIX ($(PREFIX))\n\
  uninstall       - Uninstall tsdecrypt from PREFIX\n\
\n\
Cleaning targets:\n\
  clean           - Remove tsdecrypt generated files but keep the decryption\n\
                    library config\n\
  distclean       - Remove all generated files and reset decryption library to\n\
                    dvbcsa.\n\
\n\
  make V=1          Enable verbose build\n\
  make PREFIX=dir   Set install prefix\n"
