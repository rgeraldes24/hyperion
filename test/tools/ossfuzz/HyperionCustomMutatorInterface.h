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
 * Implements libFuzzer's custom mutator interface.
 */

#pragma once

#include <test/tools/ossfuzz/HyperionGenerator.h>

#include <memory>

namespace hyperion::test::fuzzer::mutator
{
struct HyperionCustomMutatorInterface
{
	HyperionCustomMutatorInterface(uint8_t* _data, size_t _size, size_t _maxSize, unsigned _seed);
	/// Generates Hyperion test program, copies it into buffer
	/// provided by libFuzzer and @returns size of the test program.
	size_t generate();

	/// Raw pointer to libFuzzer provided input
	uint8_t* data;
	/// Size of libFuzzer provided input
	size_t size;
	/// Maximum length of mutant specified by libFuzzer
	size_t maxMutantSize;
	/// Hyperion generator handle
	std::shared_ptr<HyperionGenerator> generator;
};
}
