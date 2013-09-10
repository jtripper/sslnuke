/*
* sslnuke -- ssl.c
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

#include "../include/ssl.h"

void print_hex(unsigned char *pkt, int len) {
  int i, j;

  for(i=0, j=0; i<len; i++, j++) {
    if(j == 16) j = 0;

    printf("%02x ", pkt[i]);
    switch (j) {
      case 7:
        printf(" ");
        break;
      case 15:
        printf("\n");
        break;
    }
  }

  printf("\n\n");
}

int gen_cert(X509 **cert, EVP_PKEY **key)
{
    RSA *rsa;
    X509_NAME *subj;
    X509_EXTENSION *ext;
    X509V3_CTX ctx;
    const char *commonName = "localhost";
    char dNSName[128];
    int rc;

    *cert = NULL;
    *key = NULL;

    /* Generate a private key. */
    *key = EVP_PKEY_new();
    if (*key == NULL) {
                exit(1);
    }

    do {
        rsa = RSA_generate_key(DEFAULT_KEY_BITS, RSA_F4, NULL, NULL);
        if (rsa == NULL) {
                        exit(1);
        }
        rc = RSA_check_key(rsa);
    } while (rc == 0);
    if (rc == -1) {
                exit(1);
    }
    if (EVP_PKEY_assign_RSA(*key, rsa) == 0) {
        RSA_free(rsa);
                exit(1);
    }

    /* Generate a certificate. */
    *cert = X509_new();
    if (*cert == NULL) {
                exit(1);
    }
    if (X509_set_version(*cert, 2) == 0) /* Version 3. */ {
                exit(1);
    }

    /* Set the commonName. */
    subj = X509_get_subject_name(*cert);
    if (X509_NAME_add_entry_by_txt(subj, "commonName", MBSTRING_ASC,
        (unsigned char *) commonName, -1, -1, 0) == 0) {
                exit(1);
    }

    /* Set the dNSName. */
    rc = snprintf(dNSName, sizeof(dNSName), "DNS:%s", commonName);
    if (rc < 0 || rc >= sizeof(dNSName)) {
                exit(1);
    }
    X509V3_set_ctx(&ctx, *cert, *cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf(NULL, &ctx, "subjectAltName", dNSName);
    if (ext == NULL){
                exit(1);
    }
 
    if (X509_add_ext(*cert, ext, -1) == 0) {

                exit(1);
    }

    /* Set a comment. */
    ext = X509V3_EXT_conf(NULL, &ctx, "nsComment", CERTIFICATE_COMMENT);
    if (ext == NULL) {
                exit(1);
    }
    if (X509_add_ext(*cert, ext, -1) == 0) {
                exit(1);
    }

    X509_set_issuer_name(*cert, X509_get_subject_name(*cert));
    X509_gmtime_adj(X509_get_notBefore(*cert), 0);
    X509_gmtime_adj(X509_get_notAfter(*cert), DEFAULT_CERT_DURATION);
    X509_set_pubkey(*cert, *key);

    /* Sign it. */
    if (X509_sign(*cert, *key, EVP_sha1()) == 0) {
                exit(1);
    }

    return 1;
}


SSL_CTX* InitCTX(struct proxied_connection *conn)
{
    X509 *cert;
    EVP_PKEY *key;

    SSL_library_init();
    OpenSSL_add_all_algorithms();               /* Load cryptos, et.al. */
    SSL_load_error_strings();                   /* Bring in and register error messages */
    conn->tctx = SSL_CTX_new(SSLv3_server_method());                  /* Create new context */

    if (conn->tctx == NULL) {
        abort();
    }

    SSL_CTX_set_options(conn->tctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_cipher_list(conn->tctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    if (gen_cert(&cert, &key) == 0) {
                exit(1);
    }

    if (SSL_CTX_use_certificate(conn->tctx, cert) != 1) {
                exit(1);
    }
    if (SSL_CTX_use_PrivateKey(conn->tctx, key) != 1) {
                exit(1);
    }

    X509_free(cert);
    EVP_PKEY_free(key);

    return conn->tctx;
}

int ssl_client(struct proxied_connection *conn) {
  if(!(conn->tctx = SSL_CTX_new(SSLv23_client_method())))
    return -1;

  if(!(conn->tssl = SSL_new(conn->tctx)))
    return -1;

  if(!SSL_set_fd(conn->tssl, conn->tsock))
    return -1;

  if(SSL_connect(conn->tssl) != 1)
    return -1;

  return 1;
}

int accept_ssl(struct proxied_connection *conn) {
  char buff[65536];
  struct ssl_client_hello *hello;
  int size;

  conn->tssl = NULL;

  if((size = recv(conn->fsock, &buff, 65535, MSG_PEEK)) < sizeof(struct ssl_client_hello)) {
    printf("[!] Handshake too short.\n");
    conn->fssl = NULL;
    return 0;
  }

  hello = (struct ssl_client_hello*)buff;
  if(hello->content_type != 0x16 || hello->handshake_type != 0x01) {
    printf("[!] Wrong content (0x%x) or handshake type (0x%x).\n", hello->content_type, hello->handshake_type);
    conn->fssl = NULL;
    return 0;
  }

  if(hello->tls_version_major != 0x03 || (hello->tls_version_minor < 0x01 && hello->tls_version_minor > 0x03)) {
    printf("[!] Bad TLS version.\n");
    conn->fssl = NULL;
    return 0;
  }

  if(hello->ssl_version_major != 0x03 || (hello->ssl_version_minor < 0x01 && hello->ssl_version_minor > 0x03)) {
    printf("[!] Bad SSL version.\n");
    conn->fssl = NULL;
    return 0;
  }

  conn->fctx = InitCTX(conn);
  conn->fssl = SSL_new(conn->fctx);
  SSL_set_fd(conn->fssl, conn->fsock);
  conn->fsock = SSL_get_fd(conn->fssl);

  if(SSL_accept(conn->fssl) == -1) {
    SSL_free(conn->fssl);
    SSL_CTX_free(conn->fctx);
    conn->fssl = NULL;
    return -1;
  }

  return ssl_client(conn);
}

int read_ssl(int sock, SSL *ssl, char *buff) {
  if(ssl) {
    return SSL_read(ssl, buff, 65535);
  } else {
    return recv(sock, buff, 65535, 0);
  }
}

int send_ssl(int sock, SSL *ssl, char *buff, int size) {
  if(ssl) {
    return SSL_write(ssl, buff, size);
  } else {
    return send(sock, buff, size, 0);
  }
}

