CC = $(CROSS)$(TARGET)gcc
STRIP = $(CROSS)$(TARGET)strip
CFLAGS = -ggdb -Wall -Wextra -Wshadow -Wformat-security -Wno-strict-aliasing -O2 -D_GNU_SOURCE
RM = /bin/rm -f
Q = @

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libts
TS_LIB = $(TS_DIR)/libts.a

tsdecrypt_OBJS = data.o udp.o util.o camd.o tables.o tsdecrypt.o $(FUNCS_LIB) $(TS_LIB)
tsdecrypt_LIBS = -lcrypto -ldvbcsa -lpthread

CLEAN_OBJS = tsdecrypt $(tsdecrypt_OBJS) *~

PROGS = tsdecrypt
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
