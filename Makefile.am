bin_PROGRAMS = \
  warcsum \
  warccollres

warcsum_SOURCES = \
  warcsum.c

warcsum_CFLAGS= -Wl,-rpath -Wl,LIBDIR -lcrypto -lgzmulti -lz

 man_MANS = \
  warcsum.1 \
  warccollres.1

warccollres_SOURCES = \
  warccollres.c

warccollres_CFLAGS= -Wl,-rpath -Wl,LIBDIR -lcurl -I/usr/include/mysql -DBIG_JOINS=1 -fno-strict-aliasing -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lm -lrt -ldl -lgzmulti -lconfig -lz

dist_bin_SCRIPTS = \
  warcsumproc \
  warcsumsplit


