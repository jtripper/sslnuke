/*
* sslnuke -- conn_list.c
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

#include "../include/conn_list.h"

struct proxied_connection *add_conn(struct proxied_connection *conns) {
  struct proxied_connection *new_conn, *last;
  new_conn = (struct proxied_connection*)calloc(1, sizeof(struct proxied_connection));
  if((last = last_conn(conns))) {
    last->next = new_conn;
    new_conn->prev = last;
  } else {
    new_conn->prev = NULL;
  }

  new_conn->next = NULL;
  return new_conn;
}

struct proxied_connection *first_conn(struct proxied_connection *conns) {
  if(!conns) return conns;

  for(conns; conns->prev; conns = conns->prev);
  return conns;
}

struct proxied_connection *get_conn(int sock, struct proxied_connection *conns) {
  int index;
  conns = first_conn(conns);

  for(conns; conns->next; conns = conns->next) {
    if(conns->fsock == sock || conns->tsock == sock)
      return conns;
  }

  return NULL;
}

struct proxied_connection *last_conn(struct proxied_connection *conns) {
  if(!conns) return conns;

  for(conns; conns->next; conns = conns->next);
  return conns;
}

struct proxied_connection *rm_conn(struct proxied_connection *conn, fd_set *fds) {
  printf("[*] Connection closed.\n");
  struct proxied_connection *handle = NULL;

  if(conn->tssl) {
    SSL_free(conn->tssl);
    SSL_CTX_free(conn->tctx);
  }

  if(conn->fssl) {
    SSL_free(conn->fssl);
    SSL_CTX_free(conn->fctx);
  }

  FD_CLR(conn->tsock, fds);
  FD_CLR(conn->fsock, fds);
  shutdown(conn->tsock, SHUT_RDWR);
  close(conn->tsock);
  shutdown(conn->fsock, SHUT_RDWR);
  close(conn->fsock);

  if(conn->prev) {
    handle = conn->prev;
    conn->prev->next = conn->next;
  }

  if(conn->next) {
    handle = conn->next;
    conn->next->prev = conn->prev;
  }

  free(conn);
  return handle;
}

struct proxied_connection *rm_conn_sock(int sock, fd_set *fds, struct proxied_connection *conns) {
  struct proxied_connection *conn;

  if(!(conn = get_conn(sock, conns))) {
    return NULL;
  }

  return rm_conn(conn, fds);
}

