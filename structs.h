#ifndef TCPCLIENT__STRUCTS_H_
#define TCPCLIENT__STRUCTS_H_

#include "challenge.h"

struct LoginRequest{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
  char user[64];
  char password[32];
} __attribute__((packed)) login_request;


struct LoginResponse{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
  char code[1];
  char reason[32];
} __attribute__((packed)) login_response;

struct SubmissionRequest{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
  char name[64];
  char email[64];
  char repo[64];
} __attribute__((packed)) submission_request;

struct SubmissionResponse{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
  char token[32];
} __attribute__((packed)) submission_response;

struct LogoutRequest{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
} __attribute__((packed)) logout_request;

struct LogoutResponse{
  char msg_type;
  uint16_t msg_len;
  uint64_t timestamp;
  uint16_t check_sum;
  char reason[32];
} __attribute__((packed)) logout_response;

#endif//TCPCLIENT__STRUCTS_H_
