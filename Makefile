CC = $(CROSS)$(TARGET)gcc
STRIP = $(CROSS)$(TARGET)strip
BUILD_ID = $(shell date +%F_%R)
VERSION="v2.0"
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
CFLAGS = -ggdb -Wall -Wextra -Wshadow -Wformat-security -Wno-strict-aliasing -O2 -D_GNU_SOURCE -DBUILD_ID=\"$(BUILD_ID)\"
ifneq "$(GIT_VER)" ""
CFLAGS += -DGIT_VER=\"$(GIT_VER)\"
else
CFLAGS += -DGIT_VER=\"$(VERSION)\"
endif

RM = /bin/rm -f
Q = @

PREFIX ?= /usr/local

INSTALL = tsdecrypt
INSTALL_BIN = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libtsfuncs
TS_LIB = $(TS_DIR)/libtsfuncs.a

tsdecrypt_OBJS = data.o udp.o util.o camd.o process.o tables.o tsdecrypt.o $(FUNCS_LIB) $(TS_LIB)
tsdecrypt_LIBS = -lcrypto -ldvbcsa -lpthread

CLEAN_OBJS = tsdecrypt $(tsdecrypt_OBJS) *~

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

%.o: %.c data.h
	$(Q)echo "  CC	tsdecrypt	$<"
	$(Q)$(CC) $(CFLAGS)  -c $<

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
	@install -d "$(INSTALL_BIN)"
	@echo "INSTALL $(INSTALL) -> $(INSTALL_BIN)"
	$(Q)install $(INSTALL) "$(INSTALL_BIN)"

uninstall:
	@-for FILE in $(INSTALL); do \
		echo "RM       $(INSTALL_BIN)/$$FILE"; \
		rm "$(INSTALL_BIN)/$$FILE"; \
	done
