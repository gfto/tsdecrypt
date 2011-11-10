CC = $(CROSS)$(TARGET)gcc
STRIP = $(CROSS)$(TARGET)strip
MKDEP = $(CROSS)$(TARGET)gcc -M -o $*.d $<

BUILD_ID = $(shell date +%F_%R)
VERSION = $(shell cat RELEASE)
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
ifeq "$(GIT_VER)" ""
GIT_VER = "release"
endif

CFLAGS  = -O2 -ggdb
CFLAGS += -Wall -Wextra -Wshadow -Wformat-security
CFLAGS += -DBUILD_ID=\"$(BUILD_ID)\" -DVERSION=\"$(VERSION)\" -DGIT_VER=\"$(GIT_VER)\"

RM = /bin/rm -f
Q = @

PREFIX ?= /usr/local

INSTALL_PRG = tsdecrypt
INSTALL_PRG_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)

INSTALL_DOC = tsdecrypt.1
INSTALL_DOC_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/man/man1)

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libtsfuncs
TS_LIB = $(TS_DIR)/libtsfuncs.a

tsdecrypt_SRC  = data.c udp.c util.c camd.c process.c tables.c tsdecrypt.c
tsdecrypt_LIBS = -lcrypto -ldvbcsa -lpthread
tsdecrypt_OBJS = $(tsdecrypt_SRC:.c=.o) $(FUNCS_LIB) $(TS_LIB)

CLEAN_OBJS = tsdecrypt $(tsdecrypt_SRC:.c=.{o,d})

PROGS = tsdecrypt

.PHONY: distclean clean install uninstall

all: $(PROGS)

$(FUNCS_LIB):
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

$(TS_LIB):
	$(Q)echo "  MAKE	$(TS_LIB)"
	$(Q)$(MAKE) -s -C $(TS_DIR)

tsdecrypt: $(tsdecrypt_OBJS)
	$(Q)echo "  LINK	tsdecrypt"
	$(Q)$(CC) $(CFLAGS) $(tsdecrypt_OBJS) $(tsdecrypt_LIBS) -o tsdecrypt

%.o: %.c RELEASE
	@$(MKDEP)
	$(Q)echo "  CC	tsdecrypt	$<"
	$(Q)$(CC) $(CFLAGS)  -c $<

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
