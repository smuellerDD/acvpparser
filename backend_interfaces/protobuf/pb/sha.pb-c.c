/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/sha.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "backend_interfaces/protobuf/pb/sha.pb-c.h"
void   sha_data_msg__init
                     (ShaDataMsg         *message)
{
  static const ShaDataMsg init_value = SHA_DATA_MSG__INIT;
  *message = init_value;
}
size_t sha_data_msg__get_packed_size
                     (const ShaDataMsg *message)
{
  assert(message->base.descriptor == &sha_data_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t sha_data_msg__pack
                     (const ShaDataMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &sha_data_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t sha_data_msg__pack_to_buffer
                     (const ShaDataMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &sha_data_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
ShaDataMsg *
       sha_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (ShaDataMsg *)
     protobuf_c_message_unpack (&sha_data_msg__descriptor,
                                allocator, len, data);
}
void   sha_data_msg__free_unpacked
                     (ShaDataMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &sha_data_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor sha_data_msg__field_descriptors[8] =
{
  {
    "msg",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, msg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bitlen",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, bitlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ldt_expansion_size",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, ldt_expansion_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "outlen",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, outlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "minoutlen",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, minoutlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "maxoutlen",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, maxoutlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mac",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, mac),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cipher",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(ShaDataMsg, cipher),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned sha_data_msg__field_indices_by_name[] = {
  1,   /* field[1] = bitlen */
  7,   /* field[7] = cipher */
  2,   /* field[2] = ldt_expansion_size */
  6,   /* field[6] = mac */
  5,   /* field[5] = maxoutlen */
  4,   /* field[4] = minoutlen */
  0,   /* field[0] = msg */
  3,   /* field[3] = outlen */
};
static const ProtobufCIntRange sha_data_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor sha_data_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ShaDataMsg",
  "ShaDataMsg",
  "ShaDataMsg",
  "",
  sizeof(ShaDataMsg),
  8,
  sha_data_msg__field_descriptors,
  sha_data_msg__field_indices_by_name,
  1,  sha_data_msg__number_ranges,
  (ProtobufCMessageInit) sha_data_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
