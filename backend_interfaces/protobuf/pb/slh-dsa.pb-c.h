/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/slh-dsa.proto */

#ifndef PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fslh_2ddsa_2eproto__INCLUDED
#define PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fslh_2ddsa_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1005000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct SlhDsaKeygenDataMsg SlhDsaKeygenDataMsg;
typedef struct SlhDsaSiggenDataMsg SlhDsaSiggenDataMsg;
typedef struct SlhDsaSigverDataMsg SlhDsaSigverDataMsg;


/* --- enums --- */


/* --- messages --- */

struct  SlhDsaKeygenDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData sk_seed;
  ProtobufCBinaryData sk_prf;
  ProtobufCBinaryData pk_seed;
  ProtobufCBinaryData pk;
  ProtobufCBinaryData sk;
  uint64_t cipher;
};
#define SLH_DSA_KEYGEN_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&slh_dsa_keygen_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, 0 }


struct  SlhDsaSiggenDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData msg;
  ProtobufCBinaryData sig;
  ProtobufCBinaryData rnd;
  ProtobufCBinaryData context;
  ProtobufCBinaryData interface;
  ProtobufCBinaryData sk;
  uint64_t cipher;
  uint64_t hashalg;
};
#define SLH_DSA_SIGGEN_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&slh_dsa_siggen_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, 0, 0 }


struct  SlhDsaSigverDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData msg;
  ProtobufCBinaryData sig;
  ProtobufCBinaryData pk;
  ProtobufCBinaryData context;
  ProtobufCBinaryData interface;
  uint64_t cipher;
  uint64_t hashalg;
  uint32_t sigver_success;
};
#define SLH_DSA_SIGVER_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&slh_dsa_sigver_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, 0, 0, 0 }


/* SlhDsaKeygenDataMsg methods */
void   slh_dsa_keygen_data_msg__init
                     (SlhDsaKeygenDataMsg         *message);
size_t slh_dsa_keygen_data_msg__get_packed_size
                     (const SlhDsaKeygenDataMsg   *message);
size_t slh_dsa_keygen_data_msg__pack
                     (const SlhDsaKeygenDataMsg   *message,
                      uint8_t             *out);
size_t slh_dsa_keygen_data_msg__pack_to_buffer
                     (const SlhDsaKeygenDataMsg   *message,
                      ProtobufCBuffer     *buffer);
SlhDsaKeygenDataMsg *
       slh_dsa_keygen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   slh_dsa_keygen_data_msg__free_unpacked
                     (SlhDsaKeygenDataMsg *message,
                      ProtobufCAllocator *allocator);
/* SlhDsaSiggenDataMsg methods */
void   slh_dsa_siggen_data_msg__init
                     (SlhDsaSiggenDataMsg         *message);
size_t slh_dsa_siggen_data_msg__get_packed_size
                     (const SlhDsaSiggenDataMsg   *message);
size_t slh_dsa_siggen_data_msg__pack
                     (const SlhDsaSiggenDataMsg   *message,
                      uint8_t             *out);
size_t slh_dsa_siggen_data_msg__pack_to_buffer
                     (const SlhDsaSiggenDataMsg   *message,
                      ProtobufCBuffer     *buffer);
SlhDsaSiggenDataMsg *
       slh_dsa_siggen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   slh_dsa_siggen_data_msg__free_unpacked
                     (SlhDsaSiggenDataMsg *message,
                      ProtobufCAllocator *allocator);
/* SlhDsaSigverDataMsg methods */
void   slh_dsa_sigver_data_msg__init
                     (SlhDsaSigverDataMsg         *message);
size_t slh_dsa_sigver_data_msg__get_packed_size
                     (const SlhDsaSigverDataMsg   *message);
size_t slh_dsa_sigver_data_msg__pack
                     (const SlhDsaSigverDataMsg   *message,
                      uint8_t             *out);
size_t slh_dsa_sigver_data_msg__pack_to_buffer
                     (const SlhDsaSigverDataMsg   *message,
                      ProtobufCBuffer     *buffer);
SlhDsaSigverDataMsg *
       slh_dsa_sigver_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   slh_dsa_sigver_data_msg__free_unpacked
                     (SlhDsaSigverDataMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*SlhDsaKeygenDataMsg_Closure)
                 (const SlhDsaKeygenDataMsg *message,
                  void *closure_data);
typedef void (*SlhDsaSiggenDataMsg_Closure)
                 (const SlhDsaSiggenDataMsg *message,
                  void *closure_data);
typedef void (*SlhDsaSigverDataMsg_Closure)
                 (const SlhDsaSigverDataMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor slh_dsa_keygen_data_msg__descriptor;
extern const ProtobufCMessageDescriptor slh_dsa_siggen_data_msg__descriptor;
extern const ProtobufCMessageDescriptor slh_dsa_sigver_data_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fslh_2ddsa_2eproto__INCLUDED */
