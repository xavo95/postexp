TARGET  = postexp
OUTDIR ?= bin

CC      = xcrun -sdk iphoneos cc -arch arm64e -arch arm64 -I../include -I../offset-cache -I../patchfinder64 -Ikernel_call -I.
LDID    = ldid2
CFLAGS  = -Wall -Wno-unused-variable -Wno-unused-function

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): ../patchfinder64/*.c ../offset-cache/*.c kernel_call/*.c *.c *.m | $(OUTDIR)
	$(CC) -o $@ $^ -framework Foundation -framework IOKit $(CFLAGS)

	export LANG=C
	export LC_CTYPE=C
	export LC_ALL=C

	$(LDID) -SEnt.plist $@
	tar --disable-copyfile -cvf $(OUTDIR)/$(TARGET).tar -C $(OUTDIR) $(TARGET)
	rm -rf *.o
	rm $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
	rm -f $(OUTDIR)/$(TARGET).tar
