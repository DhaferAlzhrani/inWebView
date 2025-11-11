# ====== CONFIG ======
NDK_HOME := /home/dhafer/Android/Sdk/ndk/27.0.12077973
CLANG := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang

TARGET := aarch64-linux-android24 
CFLAGS := -fPIC -flax-vector-conversions -march=armv8-a+simd+crypto -DTARGET_PLATFORM_ARM64 -O3 -Wall
LDFLAGS := -shared
OUT := libaes_hw.so

SRC := aes_arm64.c

JNI_LIB_DIR := ../app/src/main/jniLibs/arm64-v8a


# ====== RULES ======
all: build install


build: $(OUT)

$(OUT): $(SRC)
	$(CLANG) --target=$(TARGET) $(CFLAGS) $(LDFLAGS) -o $@ $^


install: $(OUT)
	mkdir -p $(JNI_LIB_DIR)
	cp $(OUT) $(JNI_LIB_DIR)/


clean:
	rm -f $(OUT)


.PHONY: all build install clean
