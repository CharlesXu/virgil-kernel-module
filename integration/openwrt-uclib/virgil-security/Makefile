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

PKG_NAME:=virgil-security
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/virgil-security/Default
  URL:=https://virgilsecurity.com/
  MAINTAINER:=Virgil Security Support <support@virgilsecurity.com>
endef

define Package/libvirgil
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Virgil Security SDK library
  DEPENDS:=+libcurl +libstdcpp +ca-certificates
endef

define Package/libvirgil/description
 This package contains the SDK to virgil security library.
endef

define Build/Prepare
	cmake --version;							\
	mkdir -p $(PKG_BUILD_DIR);						\
	cd $(PKG_BUILD_DIR); 							\
	rm -rf virgil-sdk-cpp; 							\
	git clone "https://github.com/VirgilSecurity/virgil-sdk-cpp.git"; 	\
	cd virgil-sdk-cpp;							\
	git checkout -b 1609-wrapper --track origin/1609-wrapper
endef

define Build/Configure
	cd $(PKG_BUILD_DIR)/virgil-sdk-cpp;								\
	mkdir build; cd build;										\
	echo "PREPARE TOOLCHAIN FILE ...";								\
	echo "set(TOOLCHAIN_DIR $(TOOLCHAIN_DIR))" > "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";							\
	echo "set(TARGET_CROSS $(TARGET_CROSS))" >> "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";							\
	echo "set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $(PKG_BUILD_DIR)/virgil-sdk-cpp/build)" >> "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";\
	echo "set(STAGING_DIR $(STAGING_DIR))" >> "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";							\
	echo "" >> "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";											\
	cat  "$(PKG_BUILD_DIR)/../../../package/libs/virgil-security/virgil-openwrt.toolchain.cmake.in" >> "$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake";	\
	cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DUCLIBC=ON -DCMAKE_TOOLCHAIN_FILE="$(PKG_BUILD_DIR)/virgil-sdk-cpp/build/toolchain.cmake"
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/virgil-sdk-cpp/build/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) -rf $(PKG_BUILD_DIR)/virgil-sdk-cpp/include/virgil $(1)/usr/include/
	$(CP) -rf $(PKG_BUILD_DIR)/virgil-sdk-cpp/build/depends/installed/include/virgil $(1)/usr/include/	

	$(INSTALL_DIR) $(1)/usr/lib
	find $(PKG_BUILD_DIR)/virgil-sdk-cpp/build/ -name \lib*.so* -exec cp -dp {} $(1)/usr/lib/ \;
endef


define Package/libvirgil/install
	$(INSTALL_DIR) $(1)/usr/lib/
	find $(PKG_BUILD_DIR)/virgil-sdk-cpp/build/ -name \lib*.so* -exec cp -dp {} $(1)/usr/lib/ \;
endef

$(eval $(call BuildPackage,libvirgil))
