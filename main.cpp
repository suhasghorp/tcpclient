#include "challenge.h"

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
struct LoginRequest{
  char msg_type;
  uint16_t msg_len;
  uint64_t time;
  uint16_t check_sum;
  char user[64];
  char password[32];
} __attribute__((packed)) login_request;


struct LoginResponse{
  char msg_type;
  uint16_t msg_len;
  uint64_t time;
  uint16_t check_sum;
  char code[1];
  char reason[32];
} __attribute__((packed)) login_response;


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

uint64_t htonll(uint64_t value)
{
  // The answer is 42
  static const int num = 42;

  // Check the endianness
  if (*reinterpret_cast<const char*>(&num) == num)
  {
    const uint32_t high_part = htonl(static_cast<uint32_t>(value >> 32));
    const uint32_t low_part = htonl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));

    return (static_cast<uint64_t>(low_part) << 32) | high_part;
  } else
  {
    return value;
  }
}

void print_socket_address(const struct sockaddr *address, FILE *stream) {
  // Test for address and stream
  if (address == NULL || stream == NULL)
    return;

  void *numericAddress; // Pointer to binary address
  // Buffer to contain result (IPv6 sufficient to hold IPv4)
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
      fputs("[unknown type]", stream); // Unhandled type
      return;
  }
  // Convert binary to printable address
  if (inet_ntop(address->sa_family, numericAddress, addrBuffer,
                sizeof(addrBuffer)) == NULL)
    fputs("[invalid address]", stream); // Unable to convert
  else {
    fprintf(stream, "%s", addrBuffer);
    if (port != 0) // Zero not valid in any socket addr
      fprintf(stream, "-%u", port);
  }
}

int main(int argc, char *argv[]) {

  if (argc < 3) {
    fprintf(stderr, "usage: tcpclient hostname port\n");
    return 1;
  }

  printf("Configuring remote address...\n");
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  struct addrinfo *addr_list;
  int ret = getaddrinfo(argv[1], argv[2], &hints, &addr_list);
  if (ret != 0){
    die_with_user_message("getaddrinfo() failed", gai_strerror(ret));
  }

  int sock = -1;
  //display returned addresses
  for (struct addrinfo *addr = addr_list; addr != NULL; addr = addr->ai_next){
    print_socket_address(addr->ai_addr, stdout);
    fputc('\n', stdout);
    //try to create a reliable stream socket
    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (!ISVALIDSOCKET(sock)) {
      fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
    } else {
      printf("socket successfully created\n");
    }

    //establish connection to server
    if (connect(sock, addr->ai_addr, addr->ai_addrlen)) {
      fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
    }
  }
  // check this later
  freeaddrinfo(addr_list);

  login_request.msg_type = 'L';
  login_request.time = nanosecs();
  login_request.msg_len = 109;
  strcpy(login_request.user,"suhasghorp@gmail.com");
  strcpy(login_request.password,"pwd123");
  unsigned char *ptr=(unsigned char *)&login_request;
  int sz=sizeof(struct LoginRequest);
  login_request.check_sum = checksum16(ptr, sz);

  bool login_successful = false;

  while (!login_successful) {

    if (send(sock, (void *) &login_request, sizeof(login_request), 0) < 0) {
      printf("send failed!\n");
    } else {
      printf("login request sent\n");
    }

    if (recv(sock, &login_response, sizeof(struct LoginResponse), 0) == -1) {
      printf("receive failed!\n");
    } else {
      if (*login_response.code == 'N') {
        if (login_response.check_sum == 0) {// the reason was empty, so compare checksum
          unsigned char *ptr = (unsigned char *) &login_response;
          int sz = sizeof(struct LoginResponse);
          auto check_sum = checksum16(ptr, sz);
          printf("Login failed with reason: Checksum %d got %d\n", check_sum, login_response.check_sum);
        } else {
          printf("Login failed with reason: %s\n", login_response.reason);
        }
      } else {
        printf("Login success\n");
        login_successful = true;
      }
    }
  }

  /*if( send(sock, (void*)&login_request, sizeof(login_request),0) < 0 ) {
    printf("send failed!\n");

  if (recv (sock, &login_response, sizeof (struct LoginResponse), 0) == -1){
    printf("receive failed!\n");
  } else {
    printf("Login success\n");
  }*/







  /*printf("Remote address is: ");
  char address_buffer[100];
  char service_buffer[100];
  getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
              address_buffer, sizeof(address_buffer),
              service_buffer, sizeof(service_buffer),
              NI_NUMERICHOST);
  printf("%s %s\n", address_buffer, service_buffer);*/



  exit(0);
}
