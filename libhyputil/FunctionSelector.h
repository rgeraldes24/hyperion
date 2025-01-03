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

#pragma once

#include <libhyputil/Keccak256.h>
#include <libhyputil/FixedHash.h>

#include <string>

namespace hyperion::util
{

/// @returns the ABI selector for a given function signature, as a FixedHash h32.
inline FixedHash<4> selectorFromSignatureH32(std::string const& _signature)
{
	return FixedHash<4>(util::keccak256(_signature), FixedHash<4>::AlignLeft);
}

/// @returns the ABI selector for a given function signature, as a 32 bit number.
inline uint32_t selectorFromSignatureU32(std::string const& _signature)
{
	return uint32_t(FixedHash<4>::Arith(selectorFromSignatureH32(_signature)));
}

/// @returns the ABI selector for a given function signature, as a u256 (left aligned) number.
inline u256 selectorFromSignatureU256(std::string const& _signature)
{
	return u256(selectorFromSignatureU32(_signature)) << (256 - 32);
}

}
