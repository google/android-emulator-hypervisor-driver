# Copyright 2019 Google LLC

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# Package source codes together with release binary and symbols
# Run under WSL on Windows 10.

#!/bin/bash
cd ..
zip -r package/gvm-`date +%Y%m%d-%H%M`.zip Release/ arch/ asmgen/ gvm* virt/ __asm.* ntkrutils.* include/ assembly/
