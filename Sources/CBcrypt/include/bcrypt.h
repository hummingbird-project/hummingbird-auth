/*    $OpenBSD: bcrypt.c,v 1.58 2020/07/06 13:33:05 pirofti Exp $    */

/*
 * Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* This password hashing algorithm was designed by David Mazieres
 * <dm@lcs.mit.edu> and works as follows:
 *
 * 1. state := InitState ()
 * 2. state := ExpandKey (state, salt, password)
 * 3. REPEAT rounds:
 *      state := ExpandKey (state, 0, password)
 *    state := ExpandKey (state, 0, salt)
 * 4. ctext := "OrpheanBeholderScryDoubt"
 * 5. REPEAT 64:
 *     ctext := Encrypt_ECB (state, ctext);
 * 6. RETURN Concatenate (salt, ctext);
 *
 */

#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>

#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16    /* Precomputation is just so nice */
#define BCRYPT_WORDS 6        /* Ciphertext words */
#define BCRYPT_MINLOGROUNDS 4    /* we have log2(rounds) in salt */

#define    BCRYPT_SALTSPACE    30 /* (7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1) */
#define    BCRYPT_HASHSPACE    61

/// generate salt given a cost and random buffer of 16 bytes
int c_hb_bcrypt_initsalt_with_csalt(int log_rounds, char *salt, size_t saltbuflen, const uint8_t *csalt);
/// encrypt `pass` using `salt`
int c_hb_bcrypt_hashpass(const char *key, const char *salt, char *encrypted, size_t encryptedlen);
/// check `pass` against hash
int c_hb_bcrypt_checkpass(const char *pass, const char *goodhash);
