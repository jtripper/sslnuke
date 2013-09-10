/*
* sslnuke -- conn_list.h
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

#ifndef _CONN_LIST_H
#define _CONN_LIST_H

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/ssl.h>

struct proxied_connection {
  struct sockaddr_in to;
  struct sockaddr_in from;
  int tsock;
  int fsock;

  SSL_CTX *fctx;
  SSL     *fssl;

  SSL_CTX *tctx;
  SSL     *tssl;

  int ssl_tried;

  struct proxied_connection *prev;
  struct proxied_connection *next;
};

struct proxied_connection *add_conn(struct proxied_connection *conns);
struct proxied_connection *first_conn(struct proxied_connection *conns);
struct proxied_connection *get_conn(int sock, struct proxied_connection *conns);
struct proxied_connection *last_conn(struct proxied_connection *conns);
struct proxied_connection *rm_conn(struct proxied_connection *conn, fd_set *fds);
struct proxied_connection *rm_conn_sock(int sock, fd_set *fds, struct proxied_connection *conns);

#endif
