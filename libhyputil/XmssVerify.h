/*
	This file is part of hyperion.

	hyperion is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	hyperion is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with hyperion.  If not, see <http://www.gnu.org/licenses/>.
*/
// SPDX-License-Identifier: GPL-3.0
/**
 * XMSS signature verification compatible with theQRL/qrllib, the library used by
 * legacy QRL wallets. Backs the ``xmssverify`` precompiled contract emulation.
 */

#pragma once

#include <libhyputil/Common.h>

#include <cstddef>
#include <cstdint>

namespace hyperion::util
{

/// Size of a qrllib extended public key: 3-byte QRL descriptor || 32-byte root || 32-byte public seed.
size_t constexpr xmssExtendedPublicKeySize = 67;
/// Size of an XMSS signature without the authentication path (WOTS+ w = 16, n = 32):
/// 4-byte index || 32-byte randomness R || 67 * 32-byte WOTS+ signature.
size_t constexpr xmssSignatureBaseSize = 4 + 32 + 67 * 32;
/// Smallest and largest tree height a QRL descriptor can carry (heights are even).
unsigned constexpr xmssMinHeight = 4;
unsigned constexpr xmssMaxHeight = 30;
/// Size of the big-endian message length prefix of the precompile input.
size_t constexpr xmssVerifyMessageLengthPrefixSize = 4;

/// @returns the size of an XMSS signature for a tree of height @a _height.
inline size_t xmssSignatureSize(unsigned _height) { return xmssSignatureBaseSize + 32 * _height; }

/// Verifies the XMSS signature @a _signature over @a _message under the qrllib extended public
/// key @a _extendedPublicKey, with exactly the semantics of qrllib's
/// ``XmssBase::verify(message, signature, extended_pk)`` (Winternitz parameter w = 16):
/// - @a _extendedPublicKey must be 67 bytes: a 3-byte QRL descriptor (hash function in the low
///   nibble of byte 0 - 0 SHA2-256, 1 SHAKE-128, 2 SHAKE-256 -, signature type XMSS (0) in the
///   high nibble of byte 0, height / 2 in the low nibble of byte 1, address format SHA256_2X (0)
///   in the high nibble of byte 1 and a zero reserved byte 2), the 32-byte tree root and the
///   32-byte public seed.
/// - @a _signature must be ``2180 + 32 * height`` bytes: 4-byte big-endian leaf index, 32-byte
///   randomness R, 67 * 32-byte WOTS+ signature and ``height`` * 32-byte authentication path.
/// - @a _message is the signed data, of arbitrary length (hashed with H_msg, not pre-hashed).
/// @returns false (and never throws) for malformed keys or signatures.
bool xmssVerify(bytesConstRef _message, bytesConstRef _signature, bytesConstRef _extendedPublicKey);

/// Decodes the input of the ``xmssverify`` precompiled contract,
///   uint32 message_length (big-endian) || message || signature || extended_pk (67 bytes),
/// and verifies it with xmssVerify(). The signature is everything between the message and the
/// trailing 67-byte key, so a signature whose length does not match the key's height - and any
/// otherwise truncated or malformed input - yields false.
bool xmssVerifyPrecompileInput(bytesConstRef _input);

}
