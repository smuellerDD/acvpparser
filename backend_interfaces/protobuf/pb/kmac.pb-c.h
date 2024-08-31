/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/kmac.proto */

#ifndef PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fkmac_2eproto__INCLUDED
#define PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fkmac_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1005000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct KmacDataMsg KmacDataMsg;


/* --- enums --- */


/* --- messages --- */

struct  KmacDataMsg
{
  ProtobufCMessage base;
  ProtobufCBinaryData key;
  ProtobufCBinaryData msg;
  uint32_t maclen;
  uint32_t keylen;
  ProtobufCBinaryData mac;
  ProtobufCBinaryData customization;
  uint32_t verify_result;
  uint32_t xof_enabled;
  uint64_t cipher;
};
#define KMAC_DATA_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&kmac_data_msg__descriptor) \
, {0,NULL}, {0,NULL}, 0, 0, {0,NULL}, {0,NULL}, 0, 0, 0 }


/* KmacDataMsg methods */
void   kmac_data_msg__init
                     (KmacDataMsg         *message);
size_t kmac_data_msg__get_packed_size
                     (const KmacDataMsg   *message);
size_t kmac_data_msg__pack
                     (const KmacDataMsg   *message,
                      uint8_t             *out);
size_t kmac_data_msg__pack_to_buffer
                     (const KmacDataMsg   *message,
                      ProtobufCBuffer     *buffer);
KmacDataMsg *
       kmac_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   kmac_data_msg__free_unpacked
                     (KmacDataMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*KmacDataMsg_Closure)
                 (const KmacDataMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor kmac_data_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_backend_5finterfaces_2fprotobuf_2fpb_2fkmac_2eproto__INCLUDED */