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

static void generate_fscrypt_policy(const char *type,
			void *keytag, void *policy, size_t *plen)
{
	/*
	 * Right, its using the fscrypt context not the policy.
	 * The stuff that go at xattr should be rw by userland.?
	 * This way we could support copy and mv of files across
	 * FS without user keys.
	 */
	struct fscrypt_context *p = policy;

	*plen = sizeof(struct fscrypt_context);

	p->format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
	p->contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	p->filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	p->flags = 0;
	memcpy(p->master_key_descriptor, keytag,
				FS_KEY_DESCRIPTOR_SIZE);
	memset(p->nonce, 0, FS_KEY_DERIVATION_NONCE_SIZE);
}

int is_encryption_type_supported(const char *type)
{
	if (!strcmp(type, "fscryptv1"))
		return 1;

	return 0;
}

void print_encrypt_context(struct fscrypt_context *ctx, size_t size)
{
	int x;
	printf("fscrypt: %x %x %x\n",
		ctx->contents_encryption_mode,
		ctx->filenames_encryption_mode, ctx->flags);
	printf("mk_desc:");
	for (x = 0; x < FS_KEY_DESCRIPTOR_SIZE; x++)
		printf("%02x", ctx->master_key_descriptor[x]);
	printf("\n");
#if BTRFS_CRYPT_XATTR_INTERFACE
	printf("nonce:");
	for (x = 0; x < FS_KEY_DERIVATION_NONCE_SIZE; x++)
		printf("%02x", ctx->nonce[x]);
	printf("\n");
#endif
}

#if !BTRFS_CRYPT_XATTR_INTERFACE
static int btrfs_set_fscrypt_policy(int fd, struct fscrypt_context *p)
{
	int ret;
	struct fscrypt_policy policy = {0};

	policy.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	policy.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(policy.master_key_descriptor, p->master_key_descriptor,
						FS_KEY_DESCRIPTOR_SIZE);

	ret = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy);
	if (ret)
		return -errno;
	return 0;
}

static int btrfs_get_fscrypt_policy(int fd, u8 *val, size_t val_sz)
{
	int ret;
	struct fscrypt_policy policy;
	ret = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy);
	if (ret)
		return -errno;

	memset(val, 0, val_sz);
	memcpy(val, &policy, sizeof(struct fscrypt_policy));
	return val_sz;
}
#endif

static int handle_prop_encrypt(enum prop_object_type type, const char *object,
			const char *name, const char *etype, char *value_out)
{
	int ret;
	ssize_t sret;
	int fd = -1;
	DIR *dirstream = NULL;
	char *xattr_name = NULL;
	int open_flags = type ? O_RDWR : O_RDONLY;
	char attr_keytag[FS_KEY_DESCRIPTOR_SIZE + 1] = {0};
	char *subvol_object = strdup(object);
	key_serial_t keyserial;
	u8 policy[256] = {0};
	size_t policy_len;
	size_t val_sz = sizeof(struct fscrypt_context);
	u8 *val = NULL;
	struct fscrypt_context *ctx_org = NULL;
	struct fscrypt_context *ctx = NULL;

	ret = 0;
	fd = open_file_or_dir3(object, &dirstream, open_flags);
	if (fd == -1) {
		ret = -errno;
		error("open failed, %s:%s", object, strerror(-ret));
		goto out;
	}

	xattr_name = malloc(XATTR_BTRFS_PREFIX_LEN + strlen(name) + 1);
	if (!xattr_name) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(xattr_name, XATTR_BTRFS_PREFIX, XATTR_BTRFS_PREFIX_LEN);
	memcpy(xattr_name + XATTR_BTRFS_PREFIX_LEN, name, strlen(name));
	xattr_name[XATTR_BTRFS_PREFIX_LEN + strlen(name)] = '\0';

	val = kzalloc(val_sz, GFP_NOFS);
#if BTRFS_CRYPT_XATTR_INTERFACE
	sret = fgetxattr(fd, xattr_name, val, val_sz);
	ret = -errno;
#else
	sret = btrfs_get_fscrypt_policy(fd, val, val_sz);
	if (sret <= 0)
		ret = sret;
#endif
	if (value_out) {
		if (sret == val_sz && !ret)
			memcpy(value_out, val, val_sz);
		else
			error("attr '%s' get failed: '%s':'%s'\n",
				xattr_name, object, strerror(-ret));
		goto out;
	}
	if (!ret)
		ctx_org = (struct fscrypt_context *)val;

	if (etype && !is_encryption_type_supported(etype)) {
		error("'%s' is not enabled/found on this system\n",
					etype);
		ret = -EPROTONOSUPPORT;
		goto out;
	}

	ret = add_key_from_user(subvol_object, attr_keytag, &keyserial);
	if (ret) {
		error("Failed to create a key: %s", strerror(-ret));
		goto out;
	}

	generate_fscrypt_policy(etype, attr_keytag, &policy, &policy_len);

	ctx = (struct fscrypt_context *) policy;
	if (ctx_org && memcmp(ctx_org->master_key_descriptor,
		ctx->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE)) {
		error("Wrong passphrase");
		ret = -EINVAL;
		goto out;
	}

#if BTRFS_CRYPT_XATTR_INTERFACE
	sret = fsetxattr(fd, xattr_name, policy, policy_len, 0);
	if (sret)
		ret = -errno;
	if (sret) {
		error("failed to set attribute '%s' on '%s' : %s",
				xattr_name, policy, strerror(-ret));
		keyctl(KEYCTL_REVOKE, keyserial);
	}
#else
	sret = btrfs_set_fscrypt_policy(fd, (struct fscrypt_context *)policy);
	if (sret)
		ret = sret;
	if (sret) {
		error("failed to set fscryptv1 encryption property: %s",
				strerror(-ret));
		keyctl(KEYCTL_REVOKE, keyserial);
	}
#endif

out:
	kfree(val);
	kfree(subvol_object);
	kfree(xattr_name);
	if (fd >= 0)
		close_file_or_dir(fd, dirstream);

	return ret;
}

int prop_encrypt(enum prop_object_type type, const char *object,
				const char *name, const char *value)
{
	int ret;

	if (value) {
		/* set prop */
		ret = handle_prop_encrypt(type, object, name, value, NULL);
	} else {
		/* get prop */
		char val_out[256] = {0};
		ret = handle_prop_encrypt(type, object, name, NULL, val_out);
		if (!ret)
			print_encrypt_context((struct fscrypt_context *)val_out,
						sizeof(struct fscrypt_context));
	}
	return ret;
}
