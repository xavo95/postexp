TARGET  = postexp
OUTDIR ?= build
CURRENT_DIR = $(shell pwd)

.PHONY: all clean

all: $(OUTDIR) injector unrestrict package

injector:
	cd $(CURRENT_DIR)/examples/$@ && make && cd $(CURRENT_DIR)	

unrestrict:
	cd $(CURRENT_DIR)/examples/$@ && make && cd $(CURRENT_DIR)	

package:
	cp build/Release-iphoneos/postexp.dylib examples/bin/
	tar --disable-copyfile -cvf examples/extrabins.tar -C examples/bin .
	cp examples/extrabins.tar ../sefebreak/jailbreak-resources/tars

$(OUTDIR):
	xcodebuild -project postexp.xcodeproj -alltargets -configuration Release

clean:
	rm -rf examples/bin examples/extrabins.tar
	rm -rf $(OUTDIR)
