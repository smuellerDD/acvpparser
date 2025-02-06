obj-m += acvp_proto.o

ROOTDIR := ..
PROTODIR := $(ROOTDIR)/proto
PARSERDIR := $(ROOTDIR)/parser
BACKENDDIR := $(ROOTDIR)/backends
PROTOBACKDIR := $(ROOTDIR)/backend_interfaces/protobuf
PROTODEFDIR := $(PROTOBACKDIR)/pb

################################################################################
# Modification possible: set the relevant backend
################################################################################

# Compile the backend
acvp_proto-y := $(BACKENDDIR)/backend_leancrypto.o

# The leancrypto kernel code can link with the user space leancrypto headers
# provided they are invoked with -DLINUX_KERNEL.
ccflags-y += -DLINUX_KERNEL -I/usr/local/include

# Include the backend special code directory to compile all test code
ccflags-y += -I$(PWD)/$(ROOTDIR)/backend_interfaces/leancrypto

# The large frame is required only for the test code whose functions are not
# used anywhere else by the kernel which could lead to a blowup of the stack
# space.
ccflags-y += -Wframe-larger-than=10240

# Specify the leancrypto Linux kernel symbols file
ADDITIONALSYMBOLS := /home/sm/tmp/leancrypto-1.2.0/linux_kernel/Module.symvers

################################################################################
# End of backend setting
################################################################################

#
# ACVP-Proto code to interface with backends
#
# It is possible to remove all files except the handler code that is truly
# required to reduce the size of the resulting binary.
#
acvp_proto-y += $(PROTODIR)/proto.o			\
		$(PROTODIR)/proto_sha.o			\
		$(PROTODIR)/proto_hmac.o		\
		$(PROTODIR)/proto_sym.o			\
		$(PROTODIR)/proto_aead.o		\
		$(PROTODIR)/proto_cshake.o		\
		$(PROTODIR)/proto_kmac.o		\
		$(PROTODIR)/proto_rsa.o			\
		$(PROTODIR)/proto_drbg.o		\
		$(PROTODIR)/proto_ecdh.o		\
		$(PROTODIR)/proto_ecdsa.o		\
		$(PROTODIR)/proto_kbkdf.o		\
		$(PROTODIR)/proto_pbkdf.o		\
		$(PROTODIR)/proto_hkdf.o		\
		$(PROTODIR)/proto_ml-dsa.o		\
		$(PROTODIR)/proto_slh-dsa.o		\
		$(PROTODIR)/proto_ml-kem.o		\
		$(PROTODIR)/proto_eddsa.o

# Special Linux kernel wrapper
acvp_proto-y += proto_frontend_linux_kernel.o

# Protobuf handler code
acvp_proto-y += $(PROTOBACKDIR)/src/protobuf-c.o

#
# ACVP-Proto code for parsing the protobuf definitions
#
# It is possible to remove all files except the handler code that is truly
# required to reduce the size of the resulting binary.
#
acvp_proto-y += $(PROTODEFDIR)/ecdsa.pb-c.o		\
		$(PROTODEFDIR)/sym.pb-c.o		\
		$(PROTODEFDIR)/hmac.pb-c.o		\
		$(PROTODEFDIR)/kmac.pb-c.o		\
		$(PROTODEFDIR)/rsa.pb-c.o		\
		$(PROTODEFDIR)/ecdh.pb-c.o		\
		$(PROTODEFDIR)/aead.pb-c.o		\
		$(PROTODEFDIR)/cshake.pb-c.o		\
		$(PROTODEFDIR)/drbg.pb-c.o		\
		$(PROTODEFDIR)/sha.pb-c.o		\
		$(PROTODEFDIR)/kbkdf.pb-c.o		\
		$(PROTODEFDIR)/pbkdf.pb-c.o		\
		$(PROTODEFDIR)/kda_hkdf.pb-c.o		\
		$(PROTODEFDIR)/ml-dsa.pb-c.o		\
		$(PROTODEFDIR)/slh-dsa.pb-c.o		\
		$(PROTODEFDIR)/ml-kem.pb-c.o		\
		$(PROTODEFDIR)/eddsa.pb-c.o

# Well-selected files from parser
acvp_proto-y += $(PARSERDIR)/algorithms.o

ccflags-y += -I$(PWD) -I$(PWD)/$(ROOTDIR) -I$(PWD)/$(PARSERDIR)	\
	     -I$(PWD)/$(PROTOBACKDIR) -I$(PWD)/$(PROTODEFDIR)	\
	     -I$(PWD)/$(PROTODIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(ADDITIONALSYMBOLS) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
