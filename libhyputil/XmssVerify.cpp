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
 * XMSS signature verification compatible with theQRL/qrllib.
 *
 * This is a port of the verification half of qrllib's ``src/xmss-alt`` (itself derived from
 * the public domain XMSS reference implementation by Andreas Huelsing and Joost Rijneveld)
 * together with the argument validation of ``XmssBase::verify``. The structure deliberately
 * follows qrllib function by function (core_hash, prf, h_msg, hash_f, hash_h, gen_chain,
 * base_w, wots_pkFromSig, l_tree, validate_authpath, xmss_Verifysig) so that the two can be
 * compared side by side.
 */

#include <libhyputil/XmssVerify.h>

#include <libhyputil/Keccak256.h>
#include <libhyputil/picosha2.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace hyperion::util
{

namespace
{

// Parameters fixed by qrllib: n = 32 byte digests and WOTS+ with w = 16.
size_t constexpr n = 32;
unsigned constexpr wotsW = 16;
unsigned constexpr wotsLogW = 4;
unsigned constexpr wotsLen1 = 64;
unsigned constexpr wotsLen2 = 3;
unsigned constexpr wotsLen = wotsLen1 + wotsLen2;
size_t constexpr wotsKeySize = wotsLen * n;
size_t constexpr descriptorSize = 3;

static_assert(xmssSignatureBaseSize == 4 + n + wotsKeySize, "Signature base size mismatch.");

enum class HashFunction: uint8_t
{
	SHA2_256 = 0,
	SHAKE_128 = 1,
	SHAKE_256 = 2
};

using Digest = std::array<uint8_t, n>;
/// XMSS hash address: layer, tree (2 words), type, OTS/L-tree address, chain/tree height,
/// hash/tree index, key-and-mask.
using HashAddress = std::array<uint32_t, 8>;

/// Big-endian serialisation of @a _in into @a _bytes bytes (qrllib to_byte).
void toByte(uint8_t* _out, uint64_t _in, size_t _bytes)
{
	for (size_t i = _bytes; i > 0; --i)
	{
		_out[i - 1] = static_cast<uint8_t>(_in & 0xff);
		_in >>= 8;
	}
}

/// qrllib core_hash: Hash(toByte(type, n) || key || in), truncated to n bytes for the SHAKEs.
Digest coreHash(HashFunction _hashFunction, uint32_t _type, bytesConstRef _key, bytesConstRef _in)
{
	bytes buffer(n, 0);
	buffer.reserve(n + _key.size() + _in.size());
	toByte(buffer.data(), _type, n);
	buffer.insert(buffer.end(), _key.begin(), _key.end());
	buffer.insert(buffer.end(), _in.begin(), _in.end());

	bytes out;
	switch (_hashFunction)
	{
	case HashFunction::SHA2_256:
		out = picosha2::hash256(buffer);
		break;
	case HashFunction::SHAKE_128:
		out = shake128(buffer, n);
		break;
	case HashFunction::SHAKE_256:
		out = shake256(buffer, n);
		break;
	}

	Digest digest{};
	std::copy_n(out.begin(), n, digest.begin());
	return digest;
}

bytesConstRef digestRef(Digest const& _digest)
{
	return bytesConstRef(_digest.data(), _digest.size());
}

/// qrllib addr_to_byte: 8 big-endian 32-bit words.
bytes addressToBytes(HashAddress const& _address)
{
	bytes out(32, 0);
	for (size_t i = 0; i < 8; ++i)
		toByte(out.data() + 4 * i, _address[i], 4);
	return out;
}

/// qrllib prf: core_hash with type 3, keyed with the public seed over the hash address.
Digest prf(HashFunction _hashFunction, HashAddress const& _address, bytesConstRef _key)
{
	bytes const addressBytes = addressToBytes(_address);
	return coreHash(_hashFunction, 3, _key, bytesConstRef(&addressBytes));
}

/// qrllib h_msg: core_hash with type 2 and a 3n-byte key (R || root || index).
Digest hashMessage(HashFunction _hashFunction, bytesConstRef _key, bytesConstRef _message)
{
	return coreHash(_hashFunction, 2, _key, _message);
}

/// qrllib hash_f: WOTS+ chaining function.
Digest hashF(HashFunction _hashFunction, uint8_t const* _in, bytesConstRef _publicSeed, HashAddress& _address)
{
	_address[7] = 0;
	Digest const key = prf(_hashFunction, _address, _publicSeed);
	_address[7] = 1;
	Digest const bitmask = prf(_hashFunction, _address, _publicSeed);

	Digest buffer{};
	for (size_t i = 0; i < n; ++i)
		buffer[i] = static_cast<uint8_t>(_in[i] ^ bitmask[i]);
	return coreHash(_hashFunction, 0, digestRef(key), digestRef(buffer));
}

/// qrllib hash_h: tree node hash over two n-byte children at @a _in.
Digest hashH(HashFunction _hashFunction, uint8_t const* _in, bytesConstRef _publicSeed, HashAddress& _address)
{
	_address[7] = 0;
	Digest const key = prf(_hashFunction, _address, _publicSeed);
	_address[7] = 1;
	Digest const bitmaskLeft = prf(_hashFunction, _address, _publicSeed);
	_address[7] = 2;
	Digest const bitmaskRight = prf(_hashFunction, _address, _publicSeed);

	std::array<uint8_t, 2 * n> buffer{};
	for (size_t i = 0; i < n; ++i)
	{
		buffer[i] = static_cast<uint8_t>(_in[i] ^ bitmaskLeft[i]);
		buffer[n + i] = static_cast<uint8_t>(_in[n + i] ^ bitmaskRight[i]);
	}
	return coreHash(_hashFunction, 1, digestRef(key), bytesConstRef(buffer.data(), buffer.size()));
}

/// qrllib gen_chain: applies the chaining function to @a _in starting at chain position
/// @a _start for @a _steps steps (never beyond w - 1).
void generateChain(
	HashFunction _hashFunction,
	uint8_t* _out,
	uint8_t const* _in,
	unsigned _start,
	unsigned _steps,
	bytesConstRef _publicSeed,
	HashAddress& _address
)
{
	std::memmove(_out, _in, n);
	for (unsigned i = _start; i < _start + _steps && i < wotsW; ++i)
	{
		_address[6] = i; // setHashADRS
		Digest const digest = hashF(_hashFunction, _out, _publicSeed, _address);
		std::memcpy(_out, digest.data(), n);
	}
}

/// qrllib base_w: splits @a _input into @a _outputLength base-w digits (most significant first).
void baseW(int* _output, unsigned _outputLength, uint8_t const* _input)
{
	size_t in = 0;
	uint32_t total = 0;
	int bits = 0;
	for (unsigned consumed = 0; consumed < _outputLength; ++consumed)
	{
		if (bits == 0)
		{
			total = _input[in];
			++in;
			bits += 8;
		}
		bits -= static_cast<int>(wotsLogW);
		_output[consumed] = static_cast<int>((total >> bits) & (wotsW - 1));
	}
}

/// qrllib wots_pkFromSig: recomputes the WOTS+ public key from a signature over @a _message.
void wotsPublicKeyFromSignature(
	HashFunction _hashFunction,
	uint8_t* _publicKey,
	uint8_t const* _signature,
	uint8_t const* _message,
	bytesConstRef _publicSeed,
	HashAddress& _address
)
{
	int basew[wotsLen];
	baseW(basew, wotsLen1, _message);

	int checksum = 0;
	for (unsigned i = 0; i < wotsLen1; ++i)
		checksum += static_cast<int>(wotsW - 1) - basew[i];
	unsigned constexpr checksumShift = (8 - ((wotsLen2 * wotsLogW) % 8)) % 8;
	checksum <<= checksumShift;

	size_t constexpr checksumBytes = (wotsLen2 * wotsLogW + 7) / 8;
	uint8_t checksumSerialized[checksumBytes];
	toByte(checksumSerialized, static_cast<uint64_t>(checksum), checksumBytes);
	int checksumBaseW[wotsLen2];
	baseW(checksumBaseW, wotsLen2, checksumSerialized);
	for (unsigned i = 0; i < wotsLen2; ++i)
		basew[wotsLen1 + i] = checksumBaseW[i];

	for (unsigned i = 0; i < wotsLen; ++i)
	{
		_address[5] = i; // setChainADRS
		generateChain(
			_hashFunction,
			_publicKey + i * n,
			_signature + i * n,
			static_cast<unsigned>(basew[i]),
			wotsW - 1 - static_cast<unsigned>(basew[i]),
			_publicSeed,
			_address
		);
	}
}

/// qrllib l_tree: compresses the WOTS+ public key (modified in place) into one leaf.
Digest lTree(HashFunction _hashFunction, uint8_t* _wotsPublicKey, bytesConstRef _publicSeed, HashAddress& _address)
{
	unsigned l = wotsLen;
	uint32_t height = 0;
	_address[5] = height; // setTreeHeight
	while (l > 1)
	{
		unsigned const bound = l >> 1;
		for (unsigned i = 0; i < bound; ++i)
		{
			_address[6] = i; // setTreeIndex
			Digest const digest = hashH(_hashFunction, _wotsPublicKey + i * 2 * n, _publicSeed, _address);
			std::memcpy(_wotsPublicKey + i * n, digest.data(), n);
		}
		if (l & 1)
		{
			std::memcpy(_wotsPublicKey + (l >> 1) * n, _wotsPublicKey + (l - 1) * n, n);
			l = (l >> 1) + 1;
		}
		else
			l = l >> 1;
		++height;
		_address[5] = height;
	}
	Digest leaf{};
	std::memcpy(leaf.data(), _wotsPublicKey, n);
	return leaf;
}

/// qrllib validate_authpath: computes the tree root from a leaf and its authentication path.
Digest validateAuthenticationPath(
	HashFunction _hashFunction,
	Digest const& _leaf,
	uint32_t _leafIndex,
	uint8_t const* _authenticationPath,
	unsigned _height,
	bytesConstRef _publicSeed,
	HashAddress& _address
)
{
	std::array<uint8_t, 2 * n> buffer{};
	// If the leaf index is odd the current node is a right child and the sibling goes left.
	if (_leafIndex & 1)
	{
		std::memcpy(buffer.data() + n, _leaf.data(), n);
		std::memcpy(buffer.data(), _authenticationPath, n);
	}
	else
	{
		std::memcpy(buffer.data(), _leaf.data(), n);
		std::memcpy(buffer.data() + n, _authenticationPath, n);
	}
	_authenticationPath += n;

	for (unsigned i = 0; i < _height - 1; ++i)
	{
		_address[5] = i; // setTreeHeight
		_leafIndex >>= 1;
		_address[6] = _leafIndex; // setTreeIndex
		Digest const digest = hashH(_hashFunction, buffer.data(), _publicSeed, _address);
		if (_leafIndex & 1)
		{
			std::memcpy(buffer.data() + n, digest.data(), n);
			std::memcpy(buffer.data(), _authenticationPath, n);
		}
		else
		{
			std::memcpy(buffer.data(), digest.data(), n);
			std::memcpy(buffer.data() + n, _authenticationPath, n);
		}
		_authenticationPath += n;
	}
	_address[5] = _height - 1;
	_leafIndex >>= 1;
	_address[6] = _leafIndex;
	return hashH(_hashFunction, buffer.data(), _publicSeed, _address);
}

bool validHeight(size_t _height)
{
	return _height >= xmssMinHeight && _height <= xmssMaxHeight && (_height & 1u) == 0;
}

/// qrllib xmss_Verifysig. @a _publicKey is root || public seed (the extended key without its
/// descriptor), @a _signature has exactly ``xmssSignatureSize(_height)`` bytes.
bool verifySignature(
	HashFunction _hashFunction,
	bytesConstRef _message,
	bytesConstRef _signature,
	bytesConstRef _publicKey,
	unsigned _height
)
{
	uint8_t const* signature = _signature.data();
	uint32_t const index =
		(static_cast<uint32_t>(signature[0]) << 24) |
		(static_cast<uint32_t>(signature[1]) << 16) |
		(static_cast<uint32_t>(signature[2]) << 8) |
		static_cast<uint32_t>(signature[3]);
	if (index >= (uint32_t{1} << _height))
		return false;

	bytesConstRef const root = _publicKey.cropped(0, n);
	bytesConstRef const publicSeed = _publicKey.cropped(n, n);

	// Message hash key: R || root || toByte(index, n).
	bytes hashKey(3 * n, 0);
	std::memcpy(hashKey.data(), signature + 4, n);
	std::memcpy(hashKey.data() + n, root.data(), n);
	toByte(hashKey.data() + 2 * n, index, n);
	Digest const messageHash = hashMessage(_hashFunction, bytesConstRef(&hashKey), _message);
	signature += n + 4;

	HashAddress otsAddress{};
	HashAddress lTreeAddress{};
	HashAddress nodeAddress{};
	otsAddress[3] = 0;
	lTreeAddress[3] = 1;
	nodeAddress[3] = 2;

	// Recompute the WOTS+ public key from the signature.
	otsAddress[4] = index; // setOTSADRS
	bytes wotsPublicKey(wotsKeySize, 0);
	wotsPublicKeyFromSignature(_hashFunction, wotsPublicKey.data(), signature, messageHash.data(), publicSeed, otsAddress);
	signature += wotsKeySize;

	// Compress it into the leaf and climb the authentication path to the root.
	lTreeAddress[4] = index; // setLtreeADRS
	Digest const leaf = lTree(_hashFunction, wotsPublicKey.data(), publicSeed, lTreeAddress);
	Digest const computedRoot = validateAuthenticationPath(_hashFunction, leaf, index, signature, _height, publicSeed, nodeAddress);

	return std::equal(computedRoot.begin(), computedRoot.end(), root.begin());
}

}

bool xmssVerify(bytesConstRef _message, bytesConstRef _signature, bytesConstRef _extendedPublicKey)
{
	// Mirrors qrllib XmssBase::verify (wotsParamW = 16); every invalid_argument qrllib throws
	// internally is a false here.
	if (_extendedPublicKey.size() != xmssExtendedPublicKeySize)
		return false;
	if (_signature.size() > xmssSignatureBaseSize + xmssMaxHeight * 32)
		return false;

	// QRLDescriptor::fromExtendedPK / XmssValidation::descriptorBytes.
	uint8_t const* descriptor = _extendedPublicKey.data();
	if (descriptor[2] != 0)
		return false;
	uint8_t const hashFunction = descriptor[0] & 0x0f;
	if (hashFunction > static_cast<uint8_t>(HashFunction::SHAKE_256))
		return false;
	uint8_t const signatureType = descriptor[0] >> 4;
	uint8_t const addressFormat = (descriptor[1] >> 4) & 0x0f;
	if (addressFormat != 0) // only SHA256_2X exists
		return false;
	unsigned const height = static_cast<unsigned>(descriptor[1] & 0x0f) << 1;
	if (signatureType == 0) // XMSS
	{
		if (!validHeight(height))
			return false;
	}
	else if (signatureType == 1) // QRL multi-sig address, no tree behind it
	{
		if (height != 0)
			return false;
	}
	else
		return false;
	if (signatureType != 0)
		return false;

	// XmssBase::getHeightFromSigSize, which must agree with the descriptor.
	if (_signature.size() < xmssSignatureBaseSize)
		return false;
	if ((_signature.size() - 4) % 32 != 0)
		return false;
	size_t const signatureHeight = (_signature.size() - xmssSignatureBaseSize) / 32;
	if (!validHeight(signatureHeight))
		return false;
	if (signatureHeight != height)
		return false;

	return verifySignature(
		static_cast<HashFunction>(hashFunction),
		_message,
		_signature,
		_extendedPublicKey.cropped(descriptorSize),
		height
	);
}

bool xmssVerifyPrecompileInput(bytesConstRef _input)
{
	size_t constexpr prefixSize = xmssVerifyMessageLengthPrefixSize;
	if (_input.size() < prefixSize)
		return false;
	uint64_t const messageLength =
		(static_cast<uint64_t>(_input[0]) << 24) |
		(static_cast<uint64_t>(_input[1]) << 16) |
		(static_cast<uint64_t>(_input[2]) << 8) |
		static_cast<uint64_t>(_input[3]);
	if (static_cast<uint64_t>(_input.size()) < prefixSize + messageLength + xmssExtendedPublicKeySize)
		return false;

	size_t const messageEnd = prefixSize + static_cast<size_t>(messageLength);
	size_t const keyStart = _input.size() - xmssExtendedPublicKeySize;
	return xmssVerify(
		_input.cropped(prefixSize, static_cast<size_t>(messageLength)),
		_input.cropped(messageEnd, keyStart - messageEnd),
		_input.cropped(keyStart, xmssExtendedPublicKeySize)
	);
}

}
