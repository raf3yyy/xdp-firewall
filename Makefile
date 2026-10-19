CLANG   ?= clang
CC      ?= gcc
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MULTI   := $(shell gcc -print-multiarch 2>/dev/null)
PREFIX  ?= /usr/local

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(MULTI) -Wall
OBJ_PATH   := $(PREFIX)/lib/xdpfw/xdpfw.bpf.o

all: build/xdpfw.bpf.o build/level1.bpf.o build/xdpfw

build:
	mkdir -p build

build/%.bpf.o: src/%.bpf.c src/common.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/xdpfw: src/xdpfw.c src/common.h | build
	$(CC) -O2 -Wall -DBPF_OBJ_PATH='"$(OBJ_PATH)"' $< -o $@ -lbpf

install: all
	install -D -m 644 build/xdpfw.bpf.o $(OBJ_PATH)
	install -D -m 755 build/xdpfw $(PREFIX)/sbin/xdpfw

clean:
	rm -rf build

.PHONY: all install clean
