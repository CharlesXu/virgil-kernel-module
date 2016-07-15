#
# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT_KERNEL_MODULE_DIR:=$(shell dirname $(realpath $(ROOT_DIR)))/kernel-module
PWD := $(shell pwd)
KBUILD_EXTRA_SYMBOLS := $(ROOT_KERNEL_MODULE_DIR)/Module.symvers

ifndef KDIR
KDIR := /lib/modules/$(shell uname -r)/build
endif

SRC := src/main.c src/storage.c src/crypto.c src/certificates.c src/ieee1609dot2.c

EXTRA_CFLAGS := -I$(ROOT_DIR)/include -I$(ROOT_KERNEL_MODULE_DIR)/include -Wall

obj-m += virgil-kernel-test.o
virgil-kernel-test-objs += $(SRC:.c=.o)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules 
		
distclean:
	rm *.o *.o* .*.o.* .*.ko.*
	
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	
print-%: ; $(info $* is $(flavor $*) variable set to [$($*)]) @true
