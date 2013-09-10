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

#ifndef _MAIN_H
#define _MAIN_H

#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <sys/select.h>
#include <string.h>

#include "util.h"
#include "conn_list.h"
#include "ssl.h"
#include "parse_incoming.h"

int create_srv_sock(char *bindaddr, int bindport);
struct proxied_connection *handle_new_connection(int sock, struct proxied_connection *conns, fd_set *fds, int *high_sock);
struct proxied_connection *handle_recv(struct proxied_connection *conn, fd_set *fds, fd_set *saved);
void handle_sockets(int server_sock);
int open_connection(struct sockaddr_in *dst);

#endif
