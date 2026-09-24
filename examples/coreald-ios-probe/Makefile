SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG := $(shell xcrun --find clang)
APP := build/Payload/CoreALDProbe.app
IPA := build/CoreALDProbe.ipa

.PHONY: all clean
all: $(IPA)

$(APP)/CoreALDProbe: main.m Info.plist
	mkdir -p $(APP)
	cp Info.plist $(APP)/Info.plist
	$(CLANG) -arch arm64 -isysroot $(SDK) -miphoneos-version-min=26.0 \
		-fobjc-arc -O2 -Wall -Wextra -framework UIKit -framework Foundation \
		-o $@ main.m
	codesign --force --sign - --timestamp=none $(APP)

$(IPA): $(APP)/CoreALDProbe
	cd build && zip -q -r CoreALDProbe.ipa Payload

clean:
	rm -rf build
