TARGET  = injector
OUTDIR ?= ../iosbinpack64/usr/local/bin
POSTEXP_OUT = ../../build/Release-iphoneos

CC      = xcrun -sdk iphoneos cc -arch arm64e -arch arm64 -I$(POSTEXP_OUT)/include/postexp -L$(POSTEXP_OUT)
LDID    = ldid2
CFLAGS  = -lpostexp -lc++ -Wall

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
	$(CC) -o $@ $^ $(CFLAGS) -ObjC -framework Foundation -framework IOKit

	export LANG=C
	export LC_CTYPE=C
	export LC_ALL=C

	$(LDID) -SEnt.plist $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
