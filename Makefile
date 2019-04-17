TARGET  = postexp
OUTDIR ?= build
CURRENT_DIR = $(shell pwd)

.PHONY: all clean

all: $(OUTDIR)

$(OUTDIR):
	xcodebuild -project postexp.xcodeproj -alltargets -configuration Release
	cd $(CURRENT_DIR)/examples/injector && make && cd $(CURRENT_DIR)
	tar --disable-copyfile -cvf examples/extrabins.tar -C examples iosbinpack64
	cp examples/extrabins.tar ../sefebreak/tars/

clean:
	rm -rf examples/iosbinpack64 examples/extrabins.tar
	rm -rf $(OUTDIR)
