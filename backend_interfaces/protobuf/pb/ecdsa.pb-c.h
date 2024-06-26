/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/ecdsa.proto */

#ifndef PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fecdsa_2eproto__INCLUDED
#define PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fecdsa_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1005000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct EcdsaKeygenDataMsg EcdsaKeygenDataMsg;
typedef struct EcdsaKeygenExtraDataMsg EcdsaKeygenExtraDataMsg;
typedef struct EcdsaPkvverDataMsg EcdsaPkvverDataMsg;
typedef struct EcdsaSiggenDataMsg EcdsaSiggenDataMsg;
typedef struct EcdsaSigverDataMsg EcdsaSigverDataMsg;
typedef struct EcdsaKeygenEnMsg EcdsaKeygenEnMsg;
typedef struct EcdsaFreeKeyMsg EcdsaFreeKeyMsg;


/* --- enums --- */


/* --- messages --- */

struct  EcdsaKeygenDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData d;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  uint64_t cipher;
};
#define ECDSA_KEYGEN_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_keygen_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, 0 }


struct  EcdsaKeygenExtraDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData d;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  uint64_t cipher;
};
#define ECDSA_KEYGEN_EXTRA_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_keygen_extra_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, 0 }


struct  EcdsaPkvverDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  uint64_t cipher;
  uint32_t keyver_success;
};
#define ECDSA_PKVVER_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_pkvver_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, 0, 0 }


struct  EcdsaSiggenDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData msg;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  ProtobufCBinaryData r;
  ProtobufCBinaryData s;
  uint32_t component;
  uint64_t cipher;
  uint32_t privkey;
};
#define ECDSA_SIGGEN_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_siggen_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, 0, 0, 0 }


struct  EcdsaSigverDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData msg;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  ProtobufCBinaryData r;
  ProtobufCBinaryData s;
  uint32_t component;
  uint64_t cipher;
  uint32_t sigver_success;
};
#define ECDSA_SIGVER_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_sigver_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, {0,NULL}, 0, 0, 0 }


struct  EcdsaKeygenEnMsg
{
  ProtobufCMessage base;
  uint64_t curve;
  ProtobufCBinaryData qx;
  ProtobufCBinaryData qy;
  uint32_t privkey;
};
#define ECDSA_KEYGEN_EN_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_keygen_en_msg__descriptor) \
, 0, {0,NULL}, {0,NULL}, 0 }


struct  EcdsaFreeKeyMsg
{
  ProtobufCMessage base;
  uint32_t privkey;
};
#define ECDSA_FREE_KEY_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ecdsa_free_key_msg__descriptor) \
, 0 }


/* EcdsaKeygenDataMsg methods */
void   ecdsa_keygen_data_msg__init
                     (EcdsaKeygenDataMsg         *message);
size_t ecdsa_keygen_data_msg__get_packed_size
                     (const EcdsaKeygenDataMsg   *message);
size_t ecdsa_keygen_data_msg__pack
                     (const EcdsaKeygenDataMsg   *message,
                      uint8_t             *out);
size_t ecdsa_keygen_data_msg__pack_to_buffer
                     (const EcdsaKeygenDataMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaKeygenDataMsg *
       ecdsa_keygen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_keygen_data_msg__free_unpacked
                     (EcdsaKeygenDataMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaKeygenExtraDataMsg methods */
void   ecdsa_keygen_extra_data_msg__init
                     (EcdsaKeygenExtraDataMsg         *message);
size_t ecdsa_keygen_extra_data_msg__get_packed_size
                     (const EcdsaKeygenExtraDataMsg   *message);
size_t ecdsa_keygen_extra_data_msg__pack
                     (const EcdsaKeygenExtraDataMsg   *message,
                      uint8_t             *out);
size_t ecdsa_keygen_extra_data_msg__pack_to_buffer
                     (const EcdsaKeygenExtraDataMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaKeygenExtraDataMsg *
       ecdsa_keygen_extra_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_keygen_extra_data_msg__free_unpacked
                     (EcdsaKeygenExtraDataMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaPkvverDataMsg methods */
void   ecdsa_pkvver_data_msg__init
                     (EcdsaPkvverDataMsg         *message);
size_t ecdsa_pkvver_data_msg__get_packed_size
                     (const EcdsaPkvverDataMsg   *message);
size_t ecdsa_pkvver_data_msg__pack
                     (const EcdsaPkvverDataMsg   *message,
                      uint8_t             *out);
size_t ecdsa_pkvver_data_msg__pack_to_buffer
                     (const EcdsaPkvverDataMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaPkvverDataMsg *
       ecdsa_pkvver_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_pkvver_data_msg__free_unpacked
                     (EcdsaPkvverDataMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaSiggenDataMsg methods */
void   ecdsa_siggen_data_msg__init
                     (EcdsaSiggenDataMsg         *message);
size_t ecdsa_siggen_data_msg__get_packed_size
                     (const EcdsaSiggenDataMsg   *message);
size_t ecdsa_siggen_data_msg__pack
                     (const EcdsaSiggenDataMsg   *message,
                      uint8_t             *out);
size_t ecdsa_siggen_data_msg__pack_to_buffer
                     (const EcdsaSiggenDataMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaSiggenDataMsg *
       ecdsa_siggen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_siggen_data_msg__free_unpacked
                     (EcdsaSiggenDataMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaSigverDataMsg methods */
void   ecdsa_sigver_data_msg__init
                     (EcdsaSigverDataMsg         *message);
size_t ecdsa_sigver_data_msg__get_packed_size
                     (const EcdsaSigverDataMsg   *message);
size_t ecdsa_sigver_data_msg__pack
                     (const EcdsaSigverDataMsg   *message,
                      uint8_t             *out);
size_t ecdsa_sigver_data_msg__pack_to_buffer
                     (const EcdsaSigverDataMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaSigverDataMsg *
       ecdsa_sigver_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_sigver_data_msg__free_unpacked
                     (EcdsaSigverDataMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaKeygenEnMsg methods */
void   ecdsa_keygen_en_msg__init
                     (EcdsaKeygenEnMsg         *message);
size_t ecdsa_keygen_en_msg__get_packed_size
                     (const EcdsaKeygenEnMsg   *message);
size_t ecdsa_keygen_en_msg__pack
                     (const EcdsaKeygenEnMsg   *message,
                      uint8_t             *out);
size_t ecdsa_keygen_en_msg__pack_to_buffer
                     (const EcdsaKeygenEnMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaKeygenEnMsg *
       ecdsa_keygen_en_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_keygen_en_msg__free_unpacked
                     (EcdsaKeygenEnMsg *message,
                      ProtobufCAllocator *allocator);
/* EcdsaFreeKeyMsg methods */
void   ecdsa_free_key_msg__init
                     (EcdsaFreeKeyMsg         *message);
size_t ecdsa_free_key_msg__get_packed_size
                     (const EcdsaFreeKeyMsg   *message);
size_t ecdsa_free_key_msg__pack
                     (const EcdsaFreeKeyMsg   *message,
                      uint8_t             *out);
size_t ecdsa_free_key_msg__pack_to_buffer
                     (const EcdsaFreeKeyMsg   *message,
                      ProtobufCBuffer     *buffer);
EcdsaFreeKeyMsg *
       ecdsa_free_key_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ecdsa_free_key_msg__free_unpacked
                     (EcdsaFreeKeyMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*EcdsaKeygenDataMsg_Closure)
                 (const EcdsaKeygenDataMsg *message,
                  void *closure_data);
typedef void (*EcdsaKeygenExtraDataMsg_Closure)
                 (const EcdsaKeygenExtraDataMsg *message,
                  void *closure_data);
typedef void (*EcdsaPkvverDataMsg_Closure)
                 (const EcdsaPkvverDataMsg *message,
                  void *closure_data);
typedef void (*EcdsaSiggenDataMsg_Closure)
                 (const EcdsaSiggenDataMsg *message,
                  void *closure_data);
typedef void (*EcdsaSigverDataMsg_Closure)
                 (const EcdsaSigverDataMsg *message,
                  void *closure_data);
typedef void (*EcdsaKeygenEnMsg_Closure)
                 (const EcdsaKeygenEnMsg *message,
                  void *closure_data);
typedef void (*EcdsaFreeKeyMsg_Closure)
                 (const EcdsaFreeKeyMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor ecdsa_keygen_data_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_keygen_extra_data_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_pkvver_data_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_siggen_data_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_sigver_data_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_keygen_en_msg__descriptor;
extern const ProtobufCMessageDescriptor ecdsa_free_key_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fecdsa_2eproto__INCLUDED */
