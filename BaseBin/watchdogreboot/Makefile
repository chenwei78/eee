TARGET = watchdogreboot.dylib
CC = clang

CFLAGS = -I../.include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fblocks -O2
LDFLAGS = -dynamiclib -install_name @loader_path/$(TARGET)

sign: $(TARGET)
	@ldid -Cadhoc -S $^

$(TARGET): $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
