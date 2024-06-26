/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/aead.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "backend_interfaces/protobuf/pb/aead.pb-c.h"
void   aead_data_msg__init
                     (AeadDataMsg         *message)
{
  static const AeadDataMsg init_value = AEAD_DATA_MSG__INIT;
  *message = init_value;
}
size_t aead_data_msg__get_packed_size
                     (const AeadDataMsg *message)
{
  assert(message->base.descriptor == &aead_data_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t aead_data_msg__pack
                     (const AeadDataMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &aead_data_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t aead_data_msg__pack_to_buffer
                     (const AeadDataMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &aead_data_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AeadDataMsg *
       aead_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AeadDataMsg *)
     protobuf_c_message_unpack (&aead_data_msg__descriptor,
                                allocator, len, data);
}
void   aead_data_msg__free_unpacked
                     (AeadDataMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &aead_data_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor aead_data_msg__field_descriptors[10] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "iv",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, iv),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ivlen",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, ivlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "assoc",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, assoc),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tag",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, tag),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "taglen",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, taglen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cipher",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, cipher),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ptlen",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, ptlen),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "data",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, data),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "integrity_error",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AeadDataMsg, integrity_error),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned aead_data_msg__field_indices_by_name[] = {
  3,   /* field[3] = assoc */
  6,   /* field[6] = cipher */
  8,   /* field[8] = data */
  9,   /* field[9] = integrity_error */
  1,   /* field[1] = iv */
  2,   /* field[2] = ivlen */
  0,   /* field[0] = key */
  7,   /* field[7] = ptlen */
  4,   /* field[4] = tag */
  5,   /* field[5] = taglen */
};
static const ProtobufCIntRange aead_data_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 10 }
};
const ProtobufCMessageDescriptor aead_data_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AeadDataMsg",
  "AeadDataMsg",
  "AeadDataMsg",
  "",
  sizeof(AeadDataMsg),
  10,
  aead_data_msg__field_descriptors,
  aead_data_msg__field_indices_by_name,
  1,  aead_data_msg__number_ranges,
  (ProtobufCMessageInit) aead_data_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
