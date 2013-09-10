/*
* sslnuke -- parse_incoming.c
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

#include "../include/parse_incoming.h"

void parse_packet(int sock, struct proxied_connection *conn, char *buffer, int size) {
  char new_buff[65536];
  char *line = strtok(buffer, "\n"), *msg_index;
  char *me = inet_ntoa(conn->from.sin_addr);
  char *to, *from;

  memset(new_buff, 0, 65535);
  memcpy(new_buff, buffer, size);

  for(line = strtok(new_buff, "\n"); line != NULL; line = strtok(NULL, "\n")) {
    if(!(msg_index = strcasestr(line, "PRIVMSG")) && !(msg_index = (char*)strcasestr(line, "NOTICE")))
      continue;

    if(msg_index == line) {
      from = me;
    } else {
      *(msg_index - 1) = '\0';
      from = line + 1;
    }

    if(!(to = strchr(msg_index, ' ')))
      continue;

    to++;

    if(!(msg_index = strchr(msg_index, ':')))
      continue;

    *(msg_index - 1) = '\0';
    msg_index++;

    printf("[*] %s -> %s ", from, to);
    if(sock == conn->tsock) {
      printf("(%s): ", inet_ntoa(conn->to.sin_addr));
    } else {
      printf("(%s): ", inet_ntoa(conn->from.sin_addr));
    }

    printf("%s\n", msg_index);
  }
}
