TARGET  = injector
OUTDIR ?= ../bin
POSTEXP_OUT = ../../build/Release-iphoneos

CC      = xcrun -sdk iphoneos cc -I$(POSTEXP_OUT)/include/postexp -L$(POSTEXP_OUT)
LDID    = ldid2
CFLAGS  = -lpostexp -lc++ -Wall

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.m | $(OUTDIR)
	$(CC) -arch arm64 -o $(OUTDIR)/$(TARGET).arm64 $^ $(CFLAGS) -ObjC -framework Foundation -framework IOKit
	$(CC) -arch arm64e -o $(OUTDIR)/$(TARGET).arm64e $^ $(CFLAGS) -ObjC -framework Foundation -framework IOKit

	$(LDID) -SEnt.plist $(OUTDIR)/$(TARGET).arm64
	$(LDID) -SEnt.plist $(OUTDIR)/$(TARGET).arm64e

clean:
	rm -f $(OUTDIR)/$(TARGET).*
