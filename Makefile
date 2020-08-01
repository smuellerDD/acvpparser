#
# Copyright (C) 2017 - 2020, Stephan Mueller <smueller@chronox.de>
#
############## Configuration settings ###############

# Change as necessary
PREFIX := /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

PARSERDIR := parser

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -fPIE -O2 -Wno-long-long -Werror -DACVP_PARSER_IUT=\"$(firstword $(MAKECMDGOALS))\" -g

ifeq (/etc/lsb-release,$(wildcard /etc/lsb-release))
OS := $(shell cat /etc/lsb-release | grep DISTRIB_ID | grep -o Ubuntu)
endif

ifeq ($(OS),Ubuntu)
CFLAGS +=-DUBUNTU
else
CFLAGS +=-Wno-gnu-zero-variadic-macro-arguments
endif

#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4
# Set all symbols to hidden -- increases load time performance, forces
# entry points and ensure that the entry points are marked with visibility.h
#CFLAGS += -fvisibility=hidden -DDSO

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LDFLAGS +=-Wl,-z,relro,-z,now -pie -g
endif

NAME := acvp-parser

# Example if version information is kept in a C file
LIBMAJOR=$(shell cat $(PARSERDIR)/parser.h | grep define | grep MAJVERSION | awk '{print $$3}')
LIBMINOR=$(shell cat $(PARSERDIR)/parser.h | grep define | grep MINVERSION | awk '{print $$3}')
LIBPATCH=$(shell cat $(PARSERDIR)/parser.h | grep define | grep PATCHLEVEL | awk '{print $$3}')

################### Heavy Lifting ###################

LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)

C_SRCS := $(wildcard $(PARSERDIR)/*.c)
C_SRCS += $(wildcard $(PARSERDIR)/json-c/*.c)
C_SRCS := $(filter-out $(wildcard backend*.c), $(C_SRCS))

INCLUDE_DIRS := $(PARSERDIR)
LIBRARY_DIRS :=
LIBRARIES :=
REQUIED_FILES :=

############### CONFIGURE BACKEND ACVP2CAVS ##################

ifeq (acvp2cavs,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_acvp2cavs.c
endif

############### CONFIGURE BACKEND CAVS2ACVP ##################

ifeq (cavs2acvp,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_cavs2acvp.c
endif

################## CONFIGURE BACKEND KCAPI ###################

ifeq (kcapi,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_kcapi.c
	LIBRARIES += gcrypt gpg-error
endif

################## CONFIGURE BACKEND LIBKCAPI ################

ifeq (libkcapi,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_libkcapi.c
	LIBRARIES += kcapi
endif

################## CONFIGURE BACKEND LIBGCRYPT ################

ifeq (libgcrypt,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_libgcrypt.c
#	CFLAGS += #-I/home/$(shell echo $$USER)/hacking/sources/libs/include
#	LDFLAGS += -L/home/$(shell echo $$USER)/hacking/sources-nosync/libs/lib
	LIBRARIES += gcrypt gpg-error
endif

################## CONFIGURE BACKEND NETTLE ################

ifeq (nettle,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_nettle.c
	LIBRARIES += nettle
endif

################## CONFIGURE BACKEND GNUTLS ################
GNUTLS_SRCS = gnutls_src
GNUTLS_NETTLE_SRCS := $(GNUTLS_SRCS)/lib/nettle/int
GNUTLS_CONFIG_SRCS := $(GNUTLS_SRCS)/config.h

ifeq (gnutls,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_gnutls.c
	INCLUDE_DIRS += $(GNUTLS_SRCS)
	LIBRARIES += gnutls hogweed nettle gmp
	REQUIED_FILES += $(GNUTLS_NETTLE_SRCS) $(GNUTLS_CONFIG_SRCS)

endif

################## CONFIGURE BACKEND OPENSSL ################

ifeq (openssl,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_openssl.c
	LIBRARIES += crypto ssl
endif

################## CONFIGURE BACKEND CommonCrypto ################

ifeq (commoncrypto,$(firstword $(MAKECMDGOALS)))
	INCLUDE_DIRS += backend_interfaces/commoncrypto
	C_SRCS += backends/backend_commoncrypto.c
endif

######################################################

## CONFIGURE BACKEND CoreCrypto using the CoreCrypto cavs_dispatch interface ##

ifeq (corecrypto-dispatch,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_corecrypto_dispatch.c
	CFLAGS += -Wno-gnu-union-cast -Wno-ignored-qualifiers -Wno-pedantic -Wno-strict-aliasing
	INCLUDE_DIRS += /Users/sm/Desktop/acvp/corecrypto/DerivedData/corecrypto/Build/Products/Debug/usr/local/include \
			../corecrypto \
			backend_interfaces/corecrypto \
			/home/sm/hacking/sources-nosync/apple/corecrypto-ios11
endif

######################################################

################## CONFIGURE BACKEND CoreCrypto ################

ifeq (corecrypto,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_corecrypto.c
	CFLAGS += -Wno-gnu-union-cast -Wno-ignored-qualifiers -Wno-pedantic
	# TODO: The include pointer into ccmode is only needed to access
	# the CTR VNG implementation - do we want to claim it?
	INCLUDE_DIRS += /Users/sm/Desktop/acvp/corecrypto/DerivedData/corecrypto/Build/Products/Debug/usr/local/include \
			../corecrypto/ccmode/corecrypto/ \
			../corecrypto/cc/
endif

######################################################

################## CONFIGURE BACKEND OpenSSH ################

ifeq (openssh,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_openssh.c
endif

######################################################

################## CONFIGURE BACKEND Strongswan ################

ifeq (strongswan,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_strongswan.c
endif

######################################################

################## CONFIGURE BACKEND Libreswan ################

ifeq (libreswan,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_libreswan.c
endif

######################################################

################## CONFIGURE BACKEND NSS ################

ifeq (nss,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_pkcs11.c backends/backend_nss.c $(wildcard backend_interfaces/pkcs11/*.c)
	CFLAGS += -DENABLE_NSS=1
	# This is needed for PKCS 11 backend
	LIBRARIES += dl
	INCLUDE_DIRS += /usr/include/nss3			\
			/usr/include/nspr4			\
			backend_interfaces/pkcs11
	# This is for the NSS backend
	LIBRARIES += freebl nss3 softokn3 plc4 nspr4 nssutil3
endif

######################################################

################## CONFIGURE BACKEND ACVPProxy ########

ifeq (acvpproxy,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_acvpproxy.c $(wildcard ../acvpproxy/lib/hash/*.c)
	INCLUDE_DIRS += ../acvpproxy/lib/hash
endif

################## CONFIGURE BACKEND libsodium ########

ifeq (libsodium,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_libsodium.c
	CFLAGS += -DSODIUM
	LIBRARIES += sodium
endif

################## CONFIGURE BACKEND libnacl ########

ifeq (libnacl,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_libsodium.c
	LIBRARIES += nacl
endif

################## CONFIGURE BACKEND BoringSSL ########

BORINGSSL_LIB_A := /home/sm/hacking/repos/boringssl/build/crypto/libcrypto.a

ifeq (boringssl,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_boringssl.c
	CFLAGS :=-Wextra -Wall -O2 -Wno-long-long -Werror -DACVP_PARSER_IUT=\"$(firstword $(MAKECMDGOALS))\" -Wno-gnu-zero-variadic-macro-arguments -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4
	INCLUDE_DIRS += /home/sm/hacking/repos/boringssl/include	\
			/home/sm/hacking/repos/boringssl
	LDFLAGS :=-Wl,-z,relro,-z,now
	LDFLAGS += $(BORINGSSL_LIB_A) -lpthread
endif

################## CONFIGURE BACKEND Botan ########

ifeq (botan,$(firstword $(MAKECMDGOALS)))
	C_SRCS += backends/backend_botan.c
	INCLUDE_DIRS += /usr/include/botan-2
	LIBRARIES += botan-2
endif

################## CONFIGURE BACKEND BouncyCastle ########

ifeq (bouncycastle,$(firstword $(MAKECMDGOALS)))
	BC_DEVEL_DIR := /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.252.b09-1.fc32.x86_64
	BC_BACKEND_DIR := ${CURDIR}/backend_interfaces/bouncycastle
	BC_LIB_FILE := /usr/share/java/bcprov.jar

	CFLAGS += -Wno-pedantic -DBC_BACKEND_DIR=\"$(BC_BACKEND_DIR)\" -DBC_LIB_FILE=\"$(BC_LIB_FILE)\"
	C_SRCS += backends/backend_bouncycastle.c
	INCLUDE_DIRS += $(BC_DEVEL_DIR)/include $(BC_DEVEL_DIR)/include/linux
	LIBRARY_DIRS += $(BC_DEVEL_DIR)/jre/lib/amd64/server
	LIBRARIES += jvm
endif

################## CONFIGURE BACKEND libica ########

ifeq (libica,$(firstword $(MAKECMDGOALS)))
	CFLAGS += -Wno-strict-aliasing
	C_SRCS += backends/backend_libica.c
	LIBRARIES += ica crypto
	INCLUDE_DIRS += backend_interfaces/libica/
	INCLUDE_DIRS += backend_interfaces/cpacf/
endif

################## CONFIGURE BACKEND CPACF ########

ifeq (cpacf,$(firstword $(MAKECMDGOALS)))
	CFLAGS += -Wno-strict-aliasing
	C_SRCS += backends/backend_cpacf.c
	C_SRCS += backend_interfaces/cpacf/sha_common.c
	INCLUDE_DIRS += backend_interfaces/cpacf/
endif

######################################################

C_OBJS := ${C_SRCS:.c=.o}
CXX_OBJS := ${CXX_SRCS:.cpp=.o}
C_ASM := ${C_SRCS:.c=.s}
OBJS := $(C_OBJS) $(CXX_OBJS)
ASM := $(C_ASM)

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
CXXFLAGS += ${CFLAGS} -Wno-pedantic
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

.PHONY: clean distclean acvp2cavs cavs2acvp kcapi libkcapi libgcrypt nettle gnutls openssl nss commoncrypto corecrypto openssh strongswan libreswan acvpproxy libsodium libnacl boringssl botan bouncycastle libica default files

default:
	$(error "Usage: make <acvp2cavs|cavs2acvp|kcapi|libkcapi|libgcrypt|nettle|gnutls|openssl|nss|commoncrypto|corecrypto-dispatch|corecypto|openssh|strongswan|libreswan|acvpproxy|libsodium|libnacl|boringssl|botan|bouncycastle|libica|cpacf>")

acvp2cavs: $(NAME)
cavs2acvp: $(NAME)
kcapi: $(NAME)
libkcapi: $(NAME)
libgcrypt: $(NAME)
nettle: $(NAME)
gnutls: $(NAME)
openssl: $(NAME)
nss: $(NAME)
commoncrypto: $(NAME)
corecrypto-dispatch: $(NAME)
corecrypto: $(NAME)
openssh: $(NAME)
strongswan: $(NAME)
libreswan: $(NAME)
acvpproxy: $(NAME)
libsodium: $(NAME)
libnacl: $(NAME)
boringssl: $(NAME)
botan: $(NAME)
libica: $(NAME)
cpacf: $(NAME)
bouncycastle: $(NAME)
	javac -cp $(BC_LIB_FILE):$(BC_BACKEND_DIR)/ $(BC_BACKEND_DIR)/bc_acvp.java

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJS): | files

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

asm:
	$(foreach b, $(C_SRCS), $(CC) $(CFLAGS) -S -fverbose-asm -o ${b:.c=.s} $(b);)

clean:
	@- $(RM) $(NAME)
	@- $(RM) $(wildcard $(PARSERDIR)/*.o)
	@- $(RM) $(wildcard $(PARSERDIR)/json-c/*.o)
	@- $(RM) $(wildcard backend_interfaces/pkcs11/*.o)
	@- $(RM) $(wildcard backends/*.o)
	@- $(RM) $(ASM)
	@- $(RM) $(wildcard *.plist)
	@- $(RM) $(wildcard *$(PARSERDIR)/*.plist)
	@- $(RM) $(wildcard *$(PARSERDIR)/json-c/*.plist)
	@- $(RM) $(wildcard backend_interfaces/pkcs11/*.plist)
	@- $(RM) $(wildcard backends/*.plist)
	@- $(RM) backend_interfaces/bouncycastle//bc_acvp.class
	@- $(RM) acvpcert9.db acvpkey4.db

distclean: clean

files: $(REQUIED_FILES)

$(GNUTLS_NETTLE_SRCS):
	@echo "Checked $(GNUTLS_NETTLE_SRCS)"
	@echo "GnuTLS's Nettle sources not found in gnutls_src directory"
	@echo "Copy or symlink configured sources in gnutls_src"
	@echo "Example: ln -s $(HOME)/rpmbuild/BUILD/gnutls-3.6.8 gnutls_src"
	@false

$(GNUTLS_CONFIG_SRCS):
	@echo "Checked $(GNUTLS_CONFIG_SRCS)"
	@echo "GNuTLS's source are not configured"
	@echo "Please run $(GNUTLS_SRCS)/configure with the appropriate flags"
	@false

###############################################################################
#
# Build debugging
#
###############################################################################
show_vars:
	@echo C_SRCS=$(C_SRCS)
	@echo OBJS=$(OBJS)
	@echo PARSERDIR=$(PARSERDIR)
	@echo LIBDIR=$(LIBDIR)
	@echo USRLIBDIR=$(USRLIBDIR)
	@echo BUILDFOR=$(BUILDFOR)
	@echo LDFLAGS=$(LDFLAGS)
	@echo CFLAGS=$(CFLAGS)
