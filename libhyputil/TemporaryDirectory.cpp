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

#include <libhyputil/TemporaryDirectory.h>

#include <liblangutil/Exceptions.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#include <regex>
#include <iostream>

using namespace hyperion;
using namespace hyperion::util;

namespace fs = boost::filesystem;

TemporaryDirectory::TemporaryDirectory(std::string const& _prefix):
	m_path(fs::temp_directory_path() / fs::unique_path(_prefix + "-%%%%-%%%%-%%%%-%%%%"))
{
	// Prefix should just be a file name and not contain anything that would make us step out of /tmp.
	hypAssert(fs::path(_prefix) == fs::path(_prefix).stem(), "");

	fs::create_directory(m_path);
}

TemporaryDirectory::TemporaryDirectory(
	std::vector<boost::filesystem::path> const& _subdirectories,
	std::string const& _prefix
):
	TemporaryDirectory(_prefix)
{
	for (boost::filesystem::path const& subdirectory: _subdirectories)
	{
		hypAssert(!subdirectory.is_absolute() && subdirectory.root_path() != "/", "");
		hypAssert(
			m_path.lexically_relative(subdirectory).empty() ||
			*m_path.lexically_relative(subdirectory).begin() != "..",
			""
		);
		boost::filesystem::create_directories(m_path / subdirectory);
	}
}

TemporaryDirectory::~TemporaryDirectory()
{
	// A few paranoid sanity checks just to be extra sure we're not deleting someone's homework.
	hypAssert(m_path.string().find(fs::temp_directory_path().string()) == 0, "");
	hypAssert(!fs::equivalent(m_path, fs::temp_directory_path()), "");
	hypAssert(!fs::equivalent(m_path, m_path.root_path()), "");
	hypAssert(!m_path.empty(), "");

	boost::system::error_code errorCode;
	uintmax_t numRemoved = fs::remove_all(m_path, errorCode);
	if (errorCode.value() != boost::system::errc::success)
	{
		std::cerr << "Failed to completely remove temporary directory '" << m_path << "'. ";
		std::cerr << "Only " << numRemoved << " files were actually removed." << std::endl;
		std::cerr << "Reason: " << errorCode.message() << std::endl;
	}
}

TemporaryWorkingDirectory::TemporaryWorkingDirectory(fs::path const& _newDirectory):
	m_originalWorkingDirectory(fs::current_path())
{
	fs::current_path(_newDirectory);
}

TemporaryWorkingDirectory::~TemporaryWorkingDirectory()
{
	fs::current_path(m_originalWorkingDirectory);
}
