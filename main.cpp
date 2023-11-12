#include "challenge.h"
#include "structs.h"

using namespace std;
#define BILLION  1000000000L

uint64_t nanosecs(){
  long int ns;
  uint64_t all;
  time_t sec;
  struct timespec spec;

  clock_gettime(CLOCK_REALTIME, &spec);
  sec = spec.tv_sec;
  ns = spec.tv_nsec;

  all = (uint64_t) sec * BILLION + (uint64_t) ns;
  return all;
}

uint16_t checksum16(const uint8_t* buf, uint32_t len) {
  uint32_t sum = 0;
  for (uint32_t j = 0; j < len - 1; j += 2) {
    sum += *((uint16_t*)(&buf[j]));
  }
  if ((len & 1) != 0) {
    sum += buf[len - 1];
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  return uint16_t(~sum);
}
struct timespec res;


/* paddr: print the IP address in a standard decimal dotted format */
void paddr(unsigned char *a) {
  printf("%d.%d.%d.%d\n", a[0], a[1], a[2], a[3]);
}

void die_with_user_message(const char *msg, const char *detail) {
  fputs(msg, stderr);
  fputs(": ", stderr);
  fputs(detail, stderr);
  fputc('\n', stderr);
  exit(1);
}

void print_socket_address(const struct sockaddr *address, FILE *stream) {
  if (address == nullptr || stream == nullptr)
    return;
  void *numericAddress; // Pointer to binary address
  char addrBuffer[INET6_ADDRSTRLEN];
  in_port_t port; // Port to print
  // Set pointer to address based on address family
  switch (address->sa_family) {
    case AF_INET:
      numericAddress = &((struct sockaddr_in *) address)->sin_addr;
      port = ntohs(((struct sockaddr_in *) address)->sin_port);
      break;
    case AF_INET6:
      numericAddress = &((struct sockaddr_in6 *) address)->sin6_addr;
      port = ntohs(((struct sockaddr_in6 *) address)->sin6_port);
      break;
    default:
      fputs("[unknown type]", stream);
      return;
  }
  // Convert binary to printable address
  inet_ntop(address->sa_family, numericAddress, addrBuffer, sizeof(addrBuffer));
  fprintf(stream, "%s", addrBuffer);
}

int main(int argc, char *argv[]) {

  if (argc < 3) {
    fprintf(stderr, "usage: tcpclient hostname port\n");
    return 1;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  struct addrinfo *addr_list;
  int ret = getaddrinfo(argv[1], argv[2], &hints, &addr_list);
  if (ret != 0){
    printf("getaddrinfo() failed: %s", gai_strerror(ret));
  }

  int sock = -1;
  //display returned addresses
  for (struct addrinfo *addr = addr_list; addr != NULL; addr = addr->ai_next){
    print_socket_address(addr->ai_addr, stdout);
    fputc('\n', stdout);
    //try to create a reliable stream socket
    sock = socket(addr->ai_family, addr->ai_socktype, 0);
    if (sock < 0) {
      fprintf(stderr, "Error: (%d) (%s)\n", errno, strerror(errno));
      close(sock);
    } else {
      printf("Socket successfully created...\n");
      //establish connection to server
      if (connect(sock, addr->ai_addr, addr->ai_addrlen)) {
        fprintf(stderr, "Error: %d %s\n", errno, strerror(errno));
      }
    }
  }

  freeaddrinfo(addr_list);

  login_request.msg_type = 'L';
  login_request.timestamp = nanosecs();
  login_request.msg_len = 109;
  strcpy(login_request.user,"suhasghorp@gmail.com");
  strcpy(login_request.password,"pwd123");
  auto *ptr=(unsigned char *)&login_request;
  int sz=sizeof(struct LoginRequest);
  login_request.check_sum = checksum16(ptr, sz);

  bool login_successful = false;

  if (send(sock, (void *) &login_request, sizeof(login_request), 0) < 0) {
    printf("login send failed!\n");
  } else {
    printf("Login request sent\n");
  }

  while (!login_successful) {

    int rec_len = 0;
    rec_len = recv(sock, &login_response, sizeof(struct LoginResponse), 0);
    if (rec_len < 0){
      printf("login receive failed!\n");
    } else {
      if (*login_response.code == 'N') {
        if (login_response.check_sum == 0) {// the reason was empty, so compare checksum
          auto *rptr = (unsigned char *) &login_response;
          int sz = sizeof(struct LoginResponse);
          auto check_sum = checksum16(rptr, sz);
          printf("Login failed with reason: Checksum %d got %d\n", check_sum, login_response.check_sum);
        } else {
          printf("Login failed with reason: %s\n", login_response.reason);
        }
      } else if (*login_response.code == 'Y') {
        printf("Login success\n");
        login_successful = true;
      }
    }
  }

  //send submission request
  submission_request.msg_type = 'S';
  submission_request.timestamp = nanosecs();
  submission_request.msg_len = 205;
  strcpy(submission_request.name,"suhas ghorpadkar");
  strcpy(submission_request.email,"suhasghorp@gmail.com");
  strcpy(submission_request.repo,"github.com/suhasghorp/tcpclient");
  auto sub_ptr=(unsigned char *)&submission_request;
  sz=sizeof(struct SubmissionRequest);
  submission_request.check_sum = checksum16(sub_ptr, sz);

  int send_len = 0;
  send_len = send(sock, (void *) &submission_request, sizeof(submission_request), 0);
  if (send_len < 0){
    printf("Submission success.\n");
  } else {
    printf("SubmissionRequest request sent\n");
  }
  int rec_len = 0;
  rec_len = recv(sock, &submission_response, sizeof(struct SubmissionResponse), 0);
  if (rec_len < sizeof(SubmissionResponse)){
    printf("SubmissionResponse receive failed!\n");
  } else {
    printf("Token:%s\n", submission_response.token);
  }

  //send Logout request
  logout_request.msg_type = 'O';
  logout_request.timestamp = nanosecs();
  logout_request.msg_len = 13;
  auto logout_ptr=(unsigned char *)&logout_request;
  sz=sizeof(struct LogoutRequest);
  logout_request.check_sum = checksum16(logout_ptr, sz);

  if (send(sock, (void *) &logout_request, sizeof(logout_request), 0) < 0) {
    printf("LogoutRequest send failed!\n");
  } else {
    printf("Logout sent...\n");
  }
  if (recv(sock, &logout_response, sizeof(struct LogoutResponse), 0) == -1) {
    printf("LogoutResponse receive failed!\n");
  } else {
    printf("Logout received...\n");
  }
  exit(0);
}
