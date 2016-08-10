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
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=virgil-security-kernel
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/

include $(INCLUDE_DIR)/package.mk

define KernelPackage/virgil-security-kernel
	SUBMENU:=Cryptographic API modules
	TITLE:=Access to Virgil Security from kernel
	DEPENDS:=+virgil-service +libvirgil
	FILES:=$(PKG_BUILD_DIR)/kernel-module/virgil-kernel.ko
	AUTOLOAD:=$(call AutoLoad,1000,virgil-kernel)
endef

define Package/virgil-service
	SECTION:=utils
  	CATEGORY:=Utilities
  	TITLE:=Virgil Security Service
  	DEPENDS:=+libcurl +libstdcpp +ca-certificates +libvirgil +libpthread
endef

define KernelPackage/virgil-kernel-usage-example
	SUBMENU:=Cryptographic API modules
	TITLE:=TEST Virgil Security Kernel
	DEPENDS:=+kmod-virgil-security-kernel
	FILES:=$(PKG_BUILD_DIR)/kernel-module-tests/virgil-kernel-test.ko
endef

define KernelPackage/virgil-security-kernel/description
	Access to Virgil Security from kernel
endef

define Package/virgil-service/description
	This package contains the service for communication with kernel module.
endef

define KernelPackage/virgil-kernel-usage-example/description
	TEST Virgil Security Kernel
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR);								\
	cd $(PKG_BUILD_DIR); 									\
	rm -rf virgil-kernel; 									\
	git clone "https://github.com/VirgilSecurity/virgil-kernel-module.git"; 		\
	cd virgil-kernel-module;									\
	rm -rf .git;										\
	mv -f ./* ../;
endef

define Build/Configure
	cd $(PKG_BUILD_DIR)/user-space-service;															\
	mkdir build; cd build;																\
	echo "PREPARE TOOLCHAIN FILE ...";														\
	echo "set(TOOLCHAIN_DIR $(TOOLCHAIN_DIR))" > "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";							\
	echo "set(TARGET_CROSS $(TARGET_CROSS))" >> "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";							\
	echo "set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $(PKG_BUILD_DIR)/virgil-sdk-cpp/build)" >> "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";		\
	echo "set(STAGING_DIR $(STAGING_DIR))" >> "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";							\
	echo "" >> "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";											\
	cat  "$(PKG_BUILD_DIR)/../../../package/kernel/virgil-security-kernel/virgil-openwrt.toolchain.cmake.in" >> "$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake";	\
	cmake .. -DCMAKE_BUILD_TYPE=Release -DUCLIBC=ON -DCMAKE_TOOLCHAIN_FILE="$(PKG_BUILD_DIR)/user-space-service/build/toolchain.cmake"
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/kernel-module 	\
		KDIR="$(LINUX_DIR)" 			\
		CROSS_COMPILE="$(TARGET_CROSS)" 	\
		ARCH="$(LINUX_KARCH)" 			\
		SUBDIRS="$(PKG_BUILD_DIR)" 		\
		modules

	$(MAKE) -C $(PKG_BUILD_DIR)/kernel-module-tests \
		KDIR="$(LINUX_DIR)" 			 \
		CROSS_COMPILE="$(TARGET_CROSS)" 	 \
		ARCH="$(LINUX_KARCH)" 			 \
		SUBDIRS="$(PKG_BUILD_DIR)" 		 \
		modules

	$(MAKE) -C $(PKG_BUILD_DIR)/user-space-service/build/
endef

define KernelPackage/virgil-security-kernel/install
	true
endef

define KernelPackage/virgil-kernel-usage-example/install
	true
endef

define Package/virgil-service/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/user-space-service/build/virgil-service $(1)/usr/bin/
endef

define Build/InstallDev	
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/kernel-module/include/virgil $(1)/usr/include
endef

$(eval $(call BuildPackage,virgil-service))
$(eval $(call KernelPackage,virgil-security-kernel))
$(eval $(call KernelPackage,virgil-kernel-usage-example))
