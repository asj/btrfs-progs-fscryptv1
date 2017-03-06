/*
 * Copyright (C) 2016 Oracle.  All rights reserved.
 * Author: Anand Jain (anand.jain@oracle.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include "props.h"

#define BTRFS_CRYPTO_KEY_TYPE "logon"
#define BTRFS_CRYPTO_XATTR_INTERFACE	0

/*
 * Fixme: Use appropriate libs when that is ready.
 * Copied from fs/crypto/crypto.h
 * and include/uapi/linux/fs.h
 */

#define FS_ENCRYPTION_CONTEXT_FORMAT_V1	1
#define FS_KEY_DESCRIPTOR_SIZE		8
#define FS_MAX_KEY_SIZE			64
#define FS_KEY_DERIVATION_NONCE_SIZE	16
#define FS_ENCRYPTION_MODE_AES_256_XTS	1
#define FS_ENCRYPTION_MODE_AES_256_CTS	4
#define FS_KEY_DESC_PREFIX		"fscrypt:"
#define FS_KEY_DESC_PREFIX_SIZE		8

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct fscrypt_context {
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __attribute__ ((__packed__));

/* This is passed in from userspace into the kernel keyring */
struct fscrypt_key {
	u32 mode;
	u8 raw[FS_MAX_KEY_SIZE];
	u32 size;
} __attribute__ ((__packed__));

struct fscrypt_policy {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
} __attribute__ ((__packed__));

#define FS_IOC_SET_ENCRYPTION_POLICY    _IOR('f', 19, struct fscrypt_policy)
#define FS_IOC_GET_ENCRYPTION_PWSALT    _IOW('f', 20, __u8[16])
#define FS_IOC_GET_ENCRYPTION_POLICY    _IOW('f', 21, struct fscrypt_policy)

int is_encryption_type_supported(const char *type);
int prop_encrypt(enum prop_object_type type, const char *object,
			const char *name, const char *value);
