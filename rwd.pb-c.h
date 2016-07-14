/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: rwd.proto */

#ifndef PROTOBUF_C_rwd_2eproto__INCLUDED
#define PROTOBUF_C_rwd_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _RwdCopyReqMsg RwdCopyReqMsg;


/* --- enums --- */


/* --- messages --- */

struct  _RwdCopyReqMsg
{
  ProtobufCMessage base;
  uint32_t client_ip;
  char *uri;
};
#define RWD_COPY_REQ_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&rwd_copy_req_msg__descriptor) \
    , 0, NULL }


/* RwdCopyReqMsg methods */
void   rwd_copy_req_msg__init
                     (RwdCopyReqMsg         *message);
size_t rwd_copy_req_msg__get_packed_size
                     (const RwdCopyReqMsg   *message);
size_t rwd_copy_req_msg__pack
                     (const RwdCopyReqMsg   *message,
                      uint8_t             *out);
size_t rwd_copy_req_msg__pack_to_buffer
                     (const RwdCopyReqMsg   *message,
                      ProtobufCBuffer     *buffer);
RwdCopyReqMsg *
       rwd_copy_req_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   rwd_copy_req_msg__free_unpacked
                     (RwdCopyReqMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*RwdCopyReqMsg_Closure)
                 (const RwdCopyReqMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor rwd_copy_req_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_rwd_2eproto__INCLUDED */
