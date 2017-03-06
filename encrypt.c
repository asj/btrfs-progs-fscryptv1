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
#include <stdio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <keyutils.h>
#include <libscrypt.h>
#include <termios.h>
#include <keyutils.h>
#include <openssl/sha.h>

#include "ctree.h"
#include "commands.h"
#include "utils.h"
#include "props.h"
#include "encrypt.h"

#ifndef XATTR_BTRFS_PREFIX
#define XATTR_BTRFS_PREFIX     "btrfs."
#define XATTR_BTRFS_PREFIX_LEN (sizeof(XATTR_BTRFS_PREFIX) - 1)
#endif

/*
 * Defined as synonyms in attr/xattr.h
 */
#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

static ssize_t __get_pass(char *prompt, char **lineptr, size_t *n)
{
	struct termios old, new;
	int nread;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	/* Turn echoing off and fail if we can’t. */
	if (tcgetattr(fileno(stdin), &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* Read the password. */
	nread = getline(lineptr, n, stdin);

	/* Restore terminal. */
	tcsetattr(fileno(stdin), TCSAFLUSH, &old);

	return nread;
}

static void derive_keytag_by_key(char *subvol, u8 *m_key,
				char *keyctl_keytag, char *attr_keytag)
{
	int x, y;
	unsigned char buf[SHA256_DIGEST_LENGTH] = {0};
	unsigned char desc[SHA256_DIGEST_LENGTH] = {0};

	/* Create digest of the key and its the description/tag*/
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, m_key, FS_MAX_KEY_SIZE);
	SHA256_Final(buf, &sha256);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, buf, SHA256_DIGEST_LENGTH);
	SHA256_Final(desc, &sha256);

	strcpy(keyctl_keytag, FS_KEY_DESC_PREFIX);
	y = FS_KEY_DESC_PREFIX_SIZE;
	for (x = 0; x < FS_KEY_DESCRIPTOR_SIZE; x++) {
		sprintf(&keyctl_keytag[y], "%02x", desc[x]);
		y = y + 2;
	}
	keyctl_keytag[y] = '\0';

	memcpy(attr_keytag, desc, FS_KEY_DESCRIPTOR_SIZE);
}

/*
 * If key is set, returns its key_serial, otherwise -1
 */
static int add_key_from_user(char *subvol, char *attr_keytag,
					key_serial_t *keyserial)
{
	size_t sz;
	int retry;
	int retry_again;
	char pass_try1[100];
	char pass_try2[100];
	u8 m_key[FS_MAX_KEY_SIZE];
	size_t in_sz;
	char *pass;
	const unsigned char iv[100] = {"btrfs"};
	int ret = 0;
	int not_same = 0;
	char keyctl_keytag[100] = {0};
	struct fscrypt_key fscrypt_key;

	retry_again = 3;
again:
	pass = pass_try1;
	in_sz = sizeof(pass_try1);
	retry = 4;

	while (--retry > 0) {
		sz = __get_pass("Passphrase: ", &pass, &in_sz);
		if (!sz || sz == 1) {
			printf("\n");
			error(" Password can not be empty, pls try again");
			continue;
		}
		break;
	}
	if (retry == 0)
		return -ECANCELED;

	pass = pass_try2;
	in_sz = sizeof(pass_try1);

	printf("\n");
	sz = __get_pass("Again passphrase: ", &pass, &in_sz);
	printf("\n");
	not_same = strncmp(pass_try1, pass_try2, sz);
	if (not_same) {
		error("Password does not match\n");
		if (! --retry_again)
			return -ECANCELED;
		goto again;
	}

	ret = libscrypt_scrypt((uint8_t *)pass_try1, sz, iv, sizeof(iv),
			SCRYPT_N, SCRYPT_r, SCRYPT_p, m_key, FS_MAX_KEY_SIZE);
	if (ret) {
		error("scrypt failed, cannot derive passphrase: %d\n", ret);
		return -EFAULT;
	}

	derive_keytag_by_key(subvol, m_key, keyctl_keytag, attr_keytag);

	fscrypt_key.mode = 0;
	memcpy(&fscrypt_key.raw, m_key, FS_MAX_KEY_SIZE);
	fscrypt_key.size = FS_MAX_KEY_SIZE;

	*keyserial = add_key(BTRFS_CRYPTO_KEY_TYPE, keyctl_keytag,
				&fscrypt_key, sizeof(struct fscrypt_key),
				KEY_SPEC_USER_SESSION_KEYRING);

	if (*keyserial == -1) {
		ret = -errno;
		return ret;
	}

	return 0;
}
