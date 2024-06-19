#
# Copyright (C) 2017 - 2024, Stephan Mueller <smueller@chronox.de>
#
############## Configuration settings ###############

# Change as necessary
PREFIX := /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

PARSERDIR := parser

CC ?= cc
CFLAGS +=-Wextra -Wall -pedantic -fPIE -O2 -Wno-long-long -Werror -DACVP_PARSER_IUT=\"$(firstword $(MAKECMDGOALS))\" -g -std=c11 -Wno-variadic-macros

ifeq (/etc/lsb-release,$(wildcard /etc/lsb-release))
OS := $(shell cat /etc/lsb-release | grep DISTRIB_ID | grep -o Ubuntu)
endif

ifneq '' '$(findstring clang,$(CC))'
CFLAGS          += -Wno-gnu-zero-variadic-macro-arguments
endif

ifeq ($(OS),Ubuntu)
CFLAGS +=-DUBUNTU
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
SHLIB_NAME := libacvpparser
SHLIB_NAME_STATIC := libacvpparser_static

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

################### Include definitions ###################

include backends.mk

################### Compile ###################

C_ASM := ${C_SRCS:.c=.s}
ASM := $(C_ASM)

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
CXXFLAGS += ${CFLAGS} -Wno-pedantic
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

analyze_srcs = $(filter %.c, $(sort $(C_SRCS)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	clang --analyze $(CFLAGS) $< -o $@

scan: $(analyze_plists)

asm:
	$(foreach b, $(C_SRCS), $(CC) $(CFLAGS) -S -fverbose-asm -o ${b:.c=.s} $(b);)

clean:
	@- $(RM) $(NAME)
	@- $(RM) $(SHLIB_NAME).so
	@- $(RM) $(SHLIB_NAME_STATIC).a
	@- $(RM) $(wildcard $(PARSERDIR)/*.o)
	@- $(RM) $(wildcard $(PARSERDIR)/json-c/*.o)
	@- $(RM) $(wildcard backend_interfaces/pkcs11/*.o)
	@- $(RM) $(wildcard backend_interfaces/protobuf/src/*.o)
	@- $(RM) $(wildcard backend_interfaces/protobuf/pb/*.o)
	@- $(RM) $(wildcard backends/*.o)
	@- $(RM) $(ASM)
	@- $(RM) $(wildcard *.plist)
	@- $(RM) $(wildcard *$(PARSERDIR)/*.plist)
	@- $(RM) $(wildcard *$(PARSERDIR)/json-c/*.plist)
	@- $(RM) $(wildcard backend_interfaces/pkcs11/*.plist)
	@- $(RM) $(wildcard backend_interfaces/protobuf/src/*.plist)
	@- $(RM) $(wildcard backends/*.plist)
	@- $(RM) backend_interfaces/bouncycastle//*.class
	@- $(RM) acvpcert9.db acvpkey4.db

distclean: clean

files: $(REQUIED_FILES)

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
