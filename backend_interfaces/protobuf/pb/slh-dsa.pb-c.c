/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: backend_interfaces/protobuf/pb/slh-dsa.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "backend_interfaces/protobuf/pb/slh-dsa.pb-c.h"
void   slh_dsa_keygen_data_msg__init
                     (SlhDsaKeygenDataMsg         *message)
{
  static const SlhDsaKeygenDataMsg init_value = SLH_DSA_KEYGEN_DATA_MSG__INIT;
  *message = init_value;
}
size_t slh_dsa_keygen_data_msg__get_packed_size
                     (const SlhDsaKeygenDataMsg *message)
{
  assert(message->base.descriptor == &slh_dsa_keygen_data_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t slh_dsa_keygen_data_msg__pack
                     (const SlhDsaKeygenDataMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &slh_dsa_keygen_data_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t slh_dsa_keygen_data_msg__pack_to_buffer
                     (const SlhDsaKeygenDataMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &slh_dsa_keygen_data_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SlhDsaKeygenDataMsg *
       slh_dsa_keygen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SlhDsaKeygenDataMsg *)
     protobuf_c_message_unpack (&slh_dsa_keygen_data_msg__descriptor,
                                allocator, len, data);
}
void   slh_dsa_keygen_data_msg__free_unpacked
                     (SlhDsaKeygenDataMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &slh_dsa_keygen_data_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   slh_dsa_siggen_data_msg__init
                     (SlhDsaSiggenDataMsg         *message)
{
  static const SlhDsaSiggenDataMsg init_value = SLH_DSA_SIGGEN_DATA_MSG__INIT;
  *message = init_value;
}
size_t slh_dsa_siggen_data_msg__get_packed_size
                     (const SlhDsaSiggenDataMsg *message)
{
  assert(message->base.descriptor == &slh_dsa_siggen_data_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t slh_dsa_siggen_data_msg__pack
                     (const SlhDsaSiggenDataMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &slh_dsa_siggen_data_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t slh_dsa_siggen_data_msg__pack_to_buffer
                     (const SlhDsaSiggenDataMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &slh_dsa_siggen_data_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SlhDsaSiggenDataMsg *
       slh_dsa_siggen_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SlhDsaSiggenDataMsg *)
     protobuf_c_message_unpack (&slh_dsa_siggen_data_msg__descriptor,
                                allocator, len, data);
}
void   slh_dsa_siggen_data_msg__free_unpacked
                     (SlhDsaSiggenDataMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &slh_dsa_siggen_data_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   slh_dsa_sigver_data_msg__init
                     (SlhDsaSigverDataMsg         *message)
{
  static const SlhDsaSigverDataMsg init_value = SLH_DSA_SIGVER_DATA_MSG__INIT;
  *message = init_value;
}
size_t slh_dsa_sigver_data_msg__get_packed_size
                     (const SlhDsaSigverDataMsg *message)
{
  assert(message->base.descriptor == &slh_dsa_sigver_data_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t slh_dsa_sigver_data_msg__pack
                     (const SlhDsaSigverDataMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &slh_dsa_sigver_data_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t slh_dsa_sigver_data_msg__pack_to_buffer
                     (const SlhDsaSigverDataMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &slh_dsa_sigver_data_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SlhDsaSigverDataMsg *
       slh_dsa_sigver_data_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SlhDsaSigverDataMsg *)
     protobuf_c_message_unpack (&slh_dsa_sigver_data_msg__descriptor,
                                allocator, len, data);
}
void   slh_dsa_sigver_data_msg__free_unpacked
                     (SlhDsaSigverDataMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &slh_dsa_sigver_data_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor slh_dsa_keygen_data_msg__field_descriptors[6] =
{
  {
    "sk_seed",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, sk_seed),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sk_prf",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, sk_prf),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pk_seed",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, pk_seed),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pk",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, pk),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sk",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, sk),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cipher",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SlhDsaKeygenDataMsg, cipher),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned slh_dsa_keygen_data_msg__field_indices_by_name[] = {
  5,   /* field[5] = cipher */
  3,   /* field[3] = pk */
  2,   /* field[2] = pk_seed */
  4,   /* field[4] = sk */
  1,   /* field[1] = sk_prf */
  0,   /* field[0] = sk_seed */
};
static const ProtobufCIntRange slh_dsa_keygen_data_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor slh_dsa_keygen_data_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "SlhDsaKeygenDataMsg",
  "SlhDsaKeygenDataMsg",
  "SlhDsaKeygenDataMsg",
  "",
  sizeof(SlhDsaKeygenDataMsg),
  6,
  slh_dsa_keygen_data_msg__field_descriptors,
  slh_dsa_keygen_data_msg__field_indices_by_name,
  1,  slh_dsa_keygen_data_msg__number_ranges,
  (ProtobufCMessageInit) slh_dsa_keygen_data_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor slh_dsa_siggen_data_msg__field_descriptors[8] =
{
  {
    "msg",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, msg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sig",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, sig),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "rnd",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, rnd),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "context",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, context),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "interface",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, interface),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sk",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, sk),
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
    offsetof(SlhDsaSiggenDataMsg, cipher),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hashalg",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSiggenDataMsg, hashalg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned slh_dsa_siggen_data_msg__field_indices_by_name[] = {
  6,   /* field[6] = cipher */
  3,   /* field[3] = context */
  7,   /* field[7] = hashalg */
  4,   /* field[4] = interface */
  0,   /* field[0] = msg */
  2,   /* field[2] = rnd */
  1,   /* field[1] = sig */
  5,   /* field[5] = sk */
};
static const ProtobufCIntRange slh_dsa_siggen_data_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor slh_dsa_siggen_data_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "SlhDsaSiggenDataMsg",
  "SlhDsaSiggenDataMsg",
  "SlhDsaSiggenDataMsg",
  "",
  sizeof(SlhDsaSiggenDataMsg),
  8,
  slh_dsa_siggen_data_msg__field_descriptors,
  slh_dsa_siggen_data_msg__field_indices_by_name,
  1,  slh_dsa_siggen_data_msg__number_ranges,
  (ProtobufCMessageInit) slh_dsa_siggen_data_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor slh_dsa_sigver_data_msg__field_descriptors[8] =
{
  {
    "msg",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, msg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sig",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, sig),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pk",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, pk),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "context",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, context),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "interface",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, interface),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cipher",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, cipher),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hashalg",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, hashalg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sigver_success",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(SlhDsaSigverDataMsg, sigver_success),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned slh_dsa_sigver_data_msg__field_indices_by_name[] = {
  5,   /* field[5] = cipher */
  3,   /* field[3] = context */
  6,   /* field[6] = hashalg */
  4,   /* field[4] = interface */
  0,   /* field[0] = msg */
  2,   /* field[2] = pk */
  1,   /* field[1] = sig */
  7,   /* field[7] = sigver_success */
};
static const ProtobufCIntRange slh_dsa_sigver_data_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor slh_dsa_sigver_data_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "SlhDsaSigverDataMsg",
  "SlhDsaSigverDataMsg",
  "SlhDsaSigverDataMsg",
  "",
  sizeof(SlhDsaSigverDataMsg),
  8,
  slh_dsa_sigver_data_msg__field_descriptors,
  slh_dsa_sigver_data_msg__field_indices_by_name,
  1,  slh_dsa_sigver_data_msg__number_ranges,
  (ProtobufCMessageInit) slh_dsa_sigver_data_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
