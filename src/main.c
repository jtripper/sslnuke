/*
* sslnuke -- main.c
* (C) 2013 jtRIPper
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 1, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "../include/main.h"

// Bind to a socket
int create_srv_sock(char *bindaddr, int bindport) {
  struct sockaddr_in serv;
  int sock, yes=1;

  serv.sin_family = AF_INET;
  serv.sin_port = htons(bindport);
  serv.sin_addr.s_addr = inet_addr(bindaddr);

  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    error(1, "[!] socket");

  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    error(1, "[!] setsockopt");

  if(bind(sock, (struct sockaddr*)&serv, sizeof(struct sockaddr_in)) < 0)
    error(1, "[!] bind");

  if(listen(sock, 5) < 0)
    error(1, "[!] listen");

  return sock;
}

// Deals with incoming connections
struct proxied_connection *handle_new_connection(int sock, struct proxied_connection *conns, fd_set *fds, int *high_sock) {
  struct proxied_connection *conn;
  socklen_t csize = sizeof(struct sockaddr_in);

  // append to connection list
  conn = add_conn(conns);

  // accept the connection
  if((conn->fsock = accept(sock, (struct sockaddr*)&conn->from, &csize)) < 0) {
    error(0, "[!] accept");
    rm_conn(conn, fds);
    return NULL;
  }

  // add it to the fd_set
  FD_SET(conn->fsock, fds);
  printf("[*] Received connection from: %s:%d\n", inet_ntoa(conn->from.sin_addr), ntohs(conn->from.sin_port));

  // shamelessly ripped from: https://github.com/darkk/redsocks/blob/master/base.c#L224
  // retreives the original destination IP address
  if(getsockopt(conn->fsock, SOL_IP, SO_ORIGINAL_DST, &conn->to, &csize) < 0) {
    error(0, "[!] getsockopt");
    rm_conn(conn, fds);
    return NULL;
  }

  // open a connection with the destination server
  if((conn->tsock = open_connection(&conn->to)) < 0) {
    rm_conn(conn, fds);
    return NULL;
  }

  FD_SET(conn->tsock, fds);

  if(conn->tsock > *high_sock)
    *high_sock = conn->tsock;
  if(conn->fsock > *high_sock)
    *high_sock = conn->fsock;

  conn->ssl_tried = 0;
  return conn;
}

// recv call back
struct proxied_connection *handle_recv(struct proxied_connection *conn, fd_set *fds, fd_set *saved) {
  int bytes, insock, outsock;
  char buff[65536];
  struct proxied_connection *handle = conn;
  SSL *inssl, *outssl;

  // if the server is talking to us first, it's not SSL
  if(FD_ISSET(conn->tsock, fds)) {
    if(!conn->ssl_tried) {
      conn->ssl_tried = 1;
      printf("[*] Connection not using SSL.\n");
    }

    insock = conn->tsock;
    outsock = conn->fsock;
    inssl = conn->tssl;
    outssl = conn->fssl;
  } else if(FD_ISSET(conn->fsock, fds)) {
    // attempt to establish an SSL connection
    if(!conn->ssl_tried) {
      if(accept_ssl(conn) < 0)
        return rm_conn(conn, saved);
        
      conn->ssl_tried = 1;

      if(conn->tssl) {
        printf("[*] Connection Using SSL!\n");
        return handle;
      } else {
        printf("[*] Connection not using SSL.\n");
      }
    }

    insock = conn->fsock;
    outsock = conn->tsock;
    inssl = conn->fssl;
    outssl = conn->tssl;
  } else {
    return handle;
  }

  memset(buff, 0, 65536);
  // Read a packet, send it, and print it out
  if((bytes = read_ssl(insock, inssl, buff)) > 0) {
    send_ssl(outsock, outssl, buff, bytes);
    parse_packet(insock, conn, buff, bytes);
  } else {
    handle = rm_conn(conn, saved);
  }

  return handle;
}

// select loop
void handle_sockets(int server_sock) {
  int high_sock = server_sock;
  fd_set saved, fds;
  struct proxied_connection *conns = NULL, *conn;

  FD_ZERO(&saved);
  FD_SET(server_sock, &saved);

  for(;;) {
    fds = saved;
    select(high_sock + 1, &fds, NULL, NULL, NULL);

    if(FD_ISSET(server_sock, &fds)) {
      if((conn = handle_new_connection(server_sock, conns, &saved, &high_sock)))
        conns = conn;
    }

    if(!conns)
      continue;

    for(conn = first_conn(conns); conn; conn = conn->next) {
      if((conn = handle_recv(conn, &fds, &saved)))
        continue;
      conns = conn;
      break;
    }
  }
}

// Connect to a server
int open_connection(struct sockaddr_in *dst) {
  int sock;

  printf("[*] Opening connection to: %s:%d\n", inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));

  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    error(0, "[!] socket");
    return -1;
  }

  if(connect(sock, (struct sockaddr*)dst, sizeof(struct sockaddr_in)) < 0) {
    error(0, "[!] connect");
    return -1;
  }

  return sock;
}

int main() {
  int sock;

  sock = create_srv_sock("127.0.0.1", 4444);
  handle_sockets(sock);

  return 0;
}

