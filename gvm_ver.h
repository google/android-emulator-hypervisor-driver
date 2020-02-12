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

#define GVM_MAJOR_VERSION 1
#define GVM_MINOR_VERSION 4

#define GVM_VERSION ((GVM_MAJOR_VERSION << 16) | GVM_MINOR_VERSION)

#define GVM_RC_VERSION GVM_MAJOR_VERSION,GVM_MINOR_VERSION
#define GVM_RC_VERSION_STR _XSTR(GVM_MAJOR_VERSION) "." _XSTR(GVM_MINOR_VERSION) "\0"
