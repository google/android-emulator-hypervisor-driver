/*
 * Copyright 2019 Google LLC

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#pragma once

#define _STR(str) #str
#define _XSTR(str) _STR(str)

#define AEHD_MAJOR_VERSION 2
#define AEHD_MINOR_VERSION 1

#define AEHD_VERSION ((AEHD_MAJOR_VERSION << 16) | AEHD_MINOR_VERSION)

#define AEHD_RC_VERSION AEHD_MAJOR_VERSION,AEHD_MINOR_VERSION
#define AEHD_RC_VERSION_STR _XSTR(AEHD_MAJOR_VERSION) "." _XSTR(AEHD_MINOR_VERSION) "\0"
