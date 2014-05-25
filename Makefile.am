bin_PROGRAMS = \
  warcsum

warcsum_SOURCES = \
  warcsum.h \
  warcsum.c

dist_bin_SCRIPTS = \
  warcsumproc

#warcsum_LDADD = -lz $(pkg-config --cflags --libs glib-2.0) -lgzmulti
warcsum_LDADD = -lz -lgzmulti -lcrypto

include_HEADERS = warcsum.h
