/*
* sslnuke -- util.c
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

#include "../include/util.h"

void error(int e, char *format, ...) {
  char error_buffer[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(error_buffer, sizeof(error_buffer), format, args);
  perror(error_buffer);
  va_end(args);

  if(e) exit(1);
}

