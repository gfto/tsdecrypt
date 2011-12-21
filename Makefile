CC = $(CROSS)$(TARGET)cc
STRIP = $(CROSS)$(TARGET)strip
MKDEP = $(CC) -M -o $*.d $<
RM = /bin/rm -f

BUILD_ID = $(shell date +%F_%R)
VERSION = $(shell cat RELEASE)
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
ifeq "$(GIT_VER)" ""
GIT_VER = "release"
endif

ifndef V
Q = @
endif

CFLAGS ?= -O2 -ggdb \
 -W -Wall -Wextra \
 -Wshadow -Wformat-security -Wstrict-prototypes

DEFS = -DBUILD_ID=\"$(BUILD_ID)\" \
 -DVERSION=\"$(VERSION)\" -DGIT_VER=\"$(GIT_VER)\"

PREFIX ?= /usr/local

INSTALL_PRG = tsdecrypt
INSTALL_PRG_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)

INSTALL_DOC = tsdecrypt.1
INSTALL_DOC_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/man/man1)

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libtsfuncs
TS_LIB = $(TS_DIR)/libtsfuncs.a

tsdecrypt_SRC = data.c \
 udp.c \
 util.c \
 camd.c \
 camd-cs378x.c \
 camd-newcamd.c \
 process.c \
 tables.c \
 notify.c \
 tsdecrypt.c
tsdecrypt_LIBS = -lcrypto -ldvbcsa -lpthread
tsdecrypt_OBJS = $(FUNCS_LIB) $(TS_LIB) $(tsdecrypt_SRC:.c=.o)

ifeq "$(shell uname -s)" "Linux"
tsdecrypt_LIBS += -lcrypt
endif

CLEAN_OBJS = tsdecrypt $(tsdecrypt_SRC:.c=.{o,d})

PROGS = tsdecrypt

.PHONY: distclean clean install uninstall

all: $(PROGS)

$(FUNCS_LIB): $(FUNCS_DIR)/libfuncs.h
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

$(TS_LIB): $(TS_DIR)/tsfuncs.h $(TS_DIR)/tsdata.h
	$(Q)echo "  MAKE	$(TS_LIB)"
	$(Q)$(MAKE) -s -C $(TS_DIR)

tsdecrypt: $(tsdecrypt_OBJS)
	$(Q)echo "  LINK	tsdecrypt"
	$(Q)$(CC) $(CFLAGS) $(DEFS) $(tsdecrypt_OBJS) $(tsdecrypt_LIBS) -o tsdecrypt

%.o: %.c RELEASE
	@$(MKDEP)
	$(Q)echo "  CC	tsdecrypt	$<"
	$(Q)$(CC) $(CFLAGS) $(DEFS) -c $<

-include $(tsdecrypt_SRC:.c=.d)

strip:
	$(Q)echo "  STRIP	$(PROGS)"
	$(Q)$(STRIP) $(PROGS)

clean:
	$(Q)echo "  RM	$(CLEAN_OBJS)"
	$(Q)$(RM) $(CLEAN_OBJS)

distclean: clean
	$(Q)$(MAKE) -s -C $(TS_DIR) clean
	$(Q)$(MAKE) -s -C $(FUNCS_DIR) clean

install: all strip
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
