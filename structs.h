#ifndef TCPCLIENT__STRUCTS_H_
#define TCPCLIENT__STRUCTS_H_

#include "challenge.h"
#include <fcntl.h>
#include <string>
#include <iostream>

#define UNLIKELY(x) __builtin_expect(!!(x), 0)

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

inline auto setNonBlocking(int fd) -> bool {
  const auto flags = fcntl(fd, F_GETFL, 0);
  if (flags & O_NONBLOCK)
    return true;
  return (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1);
}

inline auto ASSERT(bool cond, const std::string &msg) noexcept {
  if (UNLIKELY(!cond)) {
    std::cerr << "ASSERT : " << msg << std::endl;

    exit(EXIT_FAILURE);
  }
}

inline auto disableNagle(int fd) -> bool {
  int one = 1;
  return (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<void *>(&one), sizeof(one)) != -1);
}


#endif//TCPCLIENT__STRUCTS_H_
