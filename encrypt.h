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

#define BTRFS_CRYPTO_KEY_TYPE "logon"

/* Copied from fs/crypto/crypto.h */
#define FS_ENCRYPTION_CONTEXT_FORMAT_V1	1
#define FS_KEY_DESCRIPTOR_SIZE		8
#define FS_MAX_KEY_SIZE			64
#define FS_KEY_DERIVATION_NONCE_SIZE	16
#define FS_ENCRYPTION_MODE_AES_256_XTS	1
#define FS_ENCRYPTION_MODE_AES_256_CTS	4
#define FS_KEY_DESC_PREFIX		"fscrypt:"
#define FS_KEY_DESC_PREFIX_SIZE		8
