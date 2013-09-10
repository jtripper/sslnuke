/*
* sslnuke -- ssl.h
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

#ifndef __SSL_H_
#define __SSL_H_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "conn_list.h"

#define DEFAULT_KEY_BITS 1024
#define DEFAULT_CERT_DURATION 60 * 60 * 24 * 365
#define CERTIFICATE_COMMENT "auto"

struct ssl_client_hello {
  char content_type; // 16 for handshake
  char tls_version_major;     // tls version
  char tls_version_minor;

  char tls_length_1;      // length
  char tls_length_2;      // length

  char handshake_type; // 1 for Client Hello

  char ssl_length_1;     // length for client hello
  char ssl_length_2;     // length for client hello
  char ssl_length_3;     // length for client hello

  char ssl_version_major;    // tls version for cliet hello
  char ssl_version_minor;    // tls version for cliet hello
};

int accept_ssl(struct proxied_connection *conn);
int read_ssl(int sock, SSL *ssl, char *buff);
int send_ssl(int sock, SSL *ssl, char *buff, int size);

#endif
