INC_DIR = . -I/usr/local/modsecurity/include

PRODUCT = bin/modsecurity-nmi.so
OS = $(shell uname -s)

CFLAGS=-g -O3 -fPIC
LDFLAGS=-shared -L/usr/local/modsecurity/lib -lmodsecurity -lxml2 -lpcre2-8 -lcurl -lstdc++ 
ifeq (${OS},Darwin)
  LDFLAGS += -Wl,-flat_namespace,-undefined,dynamic_lookup
endif


all: output ${PRODUCT}

${PRODUCT}: modsecurity-module.c
	clang ${CFLAGS} -I${INC_DIR} ${LDFLAGS} $< -o $@

output:
	@mkdir -p bin
clean:
	@rm -rf bin

