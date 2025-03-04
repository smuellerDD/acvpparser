# Protobuf Backend and ACVP-Proto

The Protobuf backend is intended to serialize the C-data structure of exactly one test case. That data blob is then expected to be forwarded to the ACVP-Proto code that is linking with the backend, unparsing the data, invoking the backend, serializing the output and returning the result to the Protobuf backend.

The objective of this logic is to have a block of data that is send across system boundaries. For example, if you have an HSM where the parser cannot be executing inside the HSM due to size constraints, you use the Protobuf backend on the host, forward the generated blob through the HSM IPC to its internal logic where the ACVP-Proto with its backend waits and processes it.

The Protobuf backend consists of the following components:

- backend_protobuf.c: This is the backend wrapped by the ACVP Parser and executing on the host.

- proto/*: This is a standalone application with the intention that its main() function may be replaced with something else to integrate with the IPC logic (and thus may become a library). This code can be directly compiled with any other backend_....c file.

- backend_interfaces/protobuf: This directory contains the protobuf header and library, as well as all protobuf definitions.

The communication logic implements the following steps.

Step  Host System                 IPC  IUT

0.    Compile ACVP-Parser and
      ACVP-Proto, copy ACVP-Proto
      to IUT and wire it up
      with the IPC mechanism,
      wire up the ACVP Parser
      with the IPC mechanism

1.    Invoke ACVP Parser with
      JSON file - for each test
      an IPC call is generated
      with the serialized
      data blob

2.    send data                   -->   ACVP-Proto receives data

3.                                      ACVP-Proto deserializes data

4.                                      ACVP-Proto invokes backend with
                                        deserialized data

5.                                      backend code invokes IUT
                                        crypto and receives answers

6.                                      ACVP-Proto serializes answers

7.    parser receives data        <--   ACVP-Proto sends data back

8.    parser deserializes data

9.    parser adds result data
      to JSON file

## Prerequisites

The following prerequisites are needed:

1. On the host compiling the ACVP Parser and the Protobuf wrapping code, the `protoc-c` compiler must be present.

Note, unlike "common" Protobuf usage, the C code of the ACVP-Proto and the ACVP-Parser do not link to the `libprotobuf` library. The C code contains a duplicate of the code which is statically linked into it.

## IPC Linkage

Both, the ACVP parser Protobuf backend and the ACVP-Proto code need some
form of connection to the IPC mechanism. The connection is established by implementing an IPC-specific send/receive function which takes as parameters the send buffer and creates the receive buffer:

* ACVP-Parser: The function `backends/backend_protobuf.c:pb_send_receive_data_implementation` needs to be adjusted. This function receives the allocated buffer to be sent which contains the header and expects to allocate the receive buffer. The header data is provided to allow a sanity check of the response buffer. The following implementations are provided in the `backend_protobuf.c` which are selected with the macros at the beginning of this file:

	- `PROTOBUF_BACKEND_EXIM_STDIN_STDOUT`: This handler code export data on STDOUT and imports data from STDIN.

	- `PROTOBUF_BACKEND_EXIM_DEBUGFS`: This handler exports data to the ACVP-Proto DebugFS file and reads the response from this file.

* ACVP-Proto: The environment-specific code in `proto_frontend_app_stdio.c` needs to be replaced. This specific logic must invoke `proto/proto.c:proto_test_algo` with the retrieved input buffer holding the protobuf blob, the header and needs to provide a buffer structure for the output that has no allocated buffers. The `proto_test_algo` function allocates the output buffer with the correct size. The following available frontends are present:

	- `proto_frontend_app_stdio.c`: This provides a user space application retrieving data from STDIN and exporting the generated data on STDOUT.

	- `linux_kernel/proto_frontend_linux_kernel.c`: This code provides the Linux kernel support retrieving the data from the DebugFS file `acvp-proto/data` that user space `write(2)`s into the file and exports the results via the same file where user space has to `read(2)` the data.

## Compilation of ACVP-Proto and associated ACVP-Parser

The ACVP-Proto code is compiled with the `Makefile.proto`. This makefile has the same calling convention as the ACVP-Parser code by requiring a parameter pointing to the backend to be wrapped. Thus, compile the code as follows:

* ACVP-Parser: `make protobuf` (in case you compile the ACVP-Proto Linux kernel support in the same code tree, see the remark for the ACVP-Proto Linux Kernel Space compilation below)

* ACVP-Proto User Space: `make -f Makefile.proto <backend>`

* ACVP-Proto Linux Kernel Space: The ACVP-Proto can be compiled for the Linux kernel space as provided in the `linux_kernel` directory. The backend must be selected in `linux_kernel/Makefile` - at the moment, only the `leancrypto` backend is supported. Once the backend is selected in the `Makefile`, compile it: `make clean && make`. Note, the kernel compilation partially compiles the same C files as the users space ACVP-Parser. As the compilation differs, you MUST do a `make clean` before the `make` invocation. The same applies when you compile the user space ACVP-Parser after you compiled the Linux kernel module.

Note, the ACVP-Proto is implemented such that it can be compiled with any backend developed for the ACVP-Parser, i.e. it uses the same registration logic and callback logic. However, at the time of writing, the ACVP-Proto does not support all algorithm types (i.e. not all algorithm types are covered with a protobuf-handler in `proto/`). Thus, it may be possible that during link time some "register_*" symbols may be found missing. In this case, the protobuf support for those algorithms needs to be added to ACVP-Proto as follows:

1. Create a new *.proto file in backend_interfaces/protobuf/pb suplicating the communicated C structure of the algorithm to be supported from the assoicated `parser_*.h`.

2. Add the new *.proto file to the `backends.mk` in the parameter `PROTOFILE` and compile the protobuf backend ACVP-Parser (`make protobuf`) to generate the C and H files from the *.proto file.

3. Add the marshalling and unmarshalling code to `backend_protobuf.c` such that the member variables of the C data structure which are marked as "[in]" are send to the ACVP-Proto and the member variables marked as "[out]" are read from the response of the ACVP-Proto.

4. Add the marshalling and unmarshalling code to ACVP-Proto by creating a new file in `proto/` similarly to the existing files. The member variables of the C data structure which are marked as "[in]" are received to the ACVP-Parser and used to fill in a local instance of the C data structure and the member variables marked as "[out]" are marshalled back to the ACVP-Parser.

Also note that with the ability to use the same unchanged backends for both, the ACVP-Parser and ACVP-Proto, it is possible that new backends can be developed in user space with ACVP-Parser. Only when the actual testing shall be performed, the newly created backend may be wrapped by the ACVP-Proto.

## Integration of ACVP Proto into other Environments

The ACVP Proto implementation does not have any external dependencies except for several POSIX calls. Specifically, see the "frontend_headers.h" file for POSIX calls that may need replacement. Further, the ACVP Proto depends on the presence of the "constructor" logic of the underlying linker. If the constructor is not offered, make sure you create a wrapper C file calling the constructor functions during initialization of the ACVP Proto (see frontend_header.h / linux_kernel/proto_frontend_linux_kernel.c:proto_init for examples).

If the intended compilation environment does not provide POSIX functions, the following approach is permissible to provide such functions without changing the ACVP Parser / Proto code base:

1. Create a header file "external_frontend_header.h" which contains the replacement code.

2. Make sure the compiler can find this header file with proper CFLAGS options (e.g. the `-I` option)

3. Set the following macro definition during compilation `__EXTERNAL_FRONTEND_HEADER__` which pulls in your `external_frontend_header.h`.

## Local Test

The local test can be achieved by the following after having the ACVP-Parser and ACVP-Proxy compiled with the STDIN/STDOUT ex/import:

1. mkfifo fifo0 fifo1

2. acvp-proto -vvv > fifo0 < fifo1

3. acvp-parser -vvv testvector-request.json testvector-response.json < fifo0 > fifo1

# Rationale

The choice of using Protobuf is based on the fact that Protobuf is supported by basically all programming languages. Thus, if the IUT code uses code other than C, the wrapper code may be implemented in that IUT language and using the Protobuf implementation of that used programming language.
