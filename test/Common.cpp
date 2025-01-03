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

#include <stdexcept>
#include <iostream>
#include <test/Common.h>
#include <test/ZVMHost.h>
#include <test/libhyperion/util/HyptestErrors.h>

#include <libhyputil/Assertions.h>
#include <libhyputil/StringUtils.h>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <range/v3/all.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;

using namespace std;

namespace hyperion::test
{

namespace
{

/// If non-empty returns the value of the env. variable ZOND_TEST_PATH, otherwise
/// it tries to find a path that contains the directories "libhyperion/syntaxTests"
/// and returns it if found.
/// The routine searches in the current directory, and inside the "test" directory
/// starting from the current directory and up to three levels up.
/// @returns the path of the first match or an empty path if not found.
boost::filesystem::path testPath()
{
	if (auto path = getenv("ZOND_TEST_PATH"))
		return path;

	auto const searchPath =
	{
		fs::current_path() / ".." / ".." / ".." / "test",
		fs::current_path() / ".." / ".." / "test",
		fs::current_path() / ".." / "test",
		fs::current_path() / "test",
		fs::current_path()
	};
	for (auto const& basePath: searchPath)
	{
		fs::path syntaxTestPath = basePath / "libhyperion" / "syntaxTests";
		if (fs::exists(syntaxTestPath) && fs::is_directory(syntaxTestPath))
			return basePath;
	}
	return {};
}

std::optional<fs::path> findInDefaultPath(std::string const& lib_name)
{
	auto const searchPath =
	{
		fs::current_path() / "deps",
		fs::current_path() / "deps" / "lib",
		fs::current_path() / ".." / "deps",
		fs::current_path() / ".." / "deps" / "lib",
		fs::current_path() / ".." / ".." / "deps",
		fs::current_path() / ".." / ".." / "deps" / "lib",
		fs::current_path()
	};
	for (auto const& basePath: searchPath)
	{
		fs::path p = basePath / lib_name;
		if (fs::exists(p))
			return p;
	}
	return std::nullopt;
}

}

CommonOptions::CommonOptions(std::string _caption):
	options(_caption,
		po::options_description::m_default_line_length,
		po::options_description::m_default_line_length - 23
	)
{

}

void CommonOptions::addOptions()
{
	options.add_options()
		("zvm-version", po::value(&zvmVersionString), "which ZVM version to use")
		("testpath", po::value<fs::path>(&this->testPath)->default_value(hyperion::test::testPath()), "path to test files")
		("vm", po::value<std::vector<fs::path>>(&vmPaths), "path to zvmc library, can be supplied multiple times.")
		("batches", po::value<size_t>(&this->batches)->default_value(1), "set number of batches to split the tests into")
		("selected-batch", po::value<size_t>(&this->selectedBatch)->default_value(0), "zero-based number of batch to execute")
		("no-semantic-tests", po::bool_switch(&disableSemanticTests)->default_value(disableSemanticTests), "disable semantic tests")
		("no-smt", po::bool_switch(&disableSMT)->default_value(disableSMT), "disable SMT checker")
		("optimize", po::bool_switch(&optimize)->default_value(optimize), "enables optimization")
		("enforce-gas-cost", po::value<bool>(&enforceGasTest)->default_value(enforceGasTest)->implicit_value(true), "Enforce checking gas cost in semantic tests.")
		("enforce-gas-cost-min-value", po::value(&enforceGasTestMinValue)->default_value(enforceGasTestMinValue), "Threshold value to enforce adding gas checks to a test.")
		("abiencoderv1", po::bool_switch(&useABIEncoderV1)->default_value(useABIEncoderV1), "enables abi encoder v1")
		("show-messages", po::bool_switch(&showMessages)->default_value(showMessages), "enables message output")
		("show-metadata", po::bool_switch(&showMetadata)->default_value(showMetadata), "enables metadata output");
}

void CommonOptions::validate() const
{
	assertThrow(
		!testPath.empty(),
		ConfigException,
		"No test path specified. The --testpath argument must not be empty when given."
	);
	assertThrow(
		fs::exists(testPath),
		ConfigException,
		"Invalid test path specified."
	);
	assertThrow(
		batches > 0,
		ConfigException,
		"Batches needs to be at least 1."
	);
	assertThrow(
		selectedBatch < batches,
		ConfigException,
		"Selected batch has to be less than number of batches."
	);

	if (enforceGasTest)
	{
		assertThrow(
			zvmVersion() == langutil::ZVMVersion{},
			ConfigException,
			"Gas costs can only be enforced on latest zvm version."
		);
		assertThrow(
			useABIEncoderV1 == false,
			ConfigException,
			"Gas costs can only be enforced on abi encoder v2."
		);
	}
}

bool CommonOptions::parse(int argc, char const* const* argv)
{
	po::variables_map arguments;
	addOptions();

	try
	{
		po::command_line_parser cmdLineParser(argc, argv);
		cmdLineParser.options(options);
		auto parsedOptions = cmdLineParser.run();
		po::store(parsedOptions, arguments);
		po::notify(arguments);

		for (auto const& parsedOption: parsedOptions.options)
			if (parsedOption.position_key >= 0)
			{
				if (
					parsedOption.original_tokens.empty() ||
					(parsedOption.original_tokens.size() == 1 && parsedOption.original_tokens.front().empty())
				)
					continue; // ignore empty options
				std::stringstream errorMessage;
				errorMessage << "Unrecognized option: ";
				for (auto const& token: parsedOption.original_tokens)
					errorMessage << token;
				BOOST_THROW_EXCEPTION(std::runtime_error(errorMessage.str()));
			}
	}
	catch (po::error const& exception)
	{
		hypThrow(ConfigException, exception.what());
	}

	if (vmPaths.empty())
	{
		if (auto envPath = getenv("ZOND_ZVMONE"))
			vmPaths.emplace_back(envPath);
		else if (auto repoPath = findInDefaultPath(zvmoneFilename))
			vmPaths.emplace_back(*repoPath);
		else
			vmPaths.emplace_back(zvmoneFilename);
	}

	return true;
}

string CommonOptions::toString(vector<string> const& _selectedOptions) const
{
	if (_selectedOptions.empty())
		return "";

	auto boolToString = [](bool _value) -> string { return _value ? "true" : "false"; };
	// Using std::map to avoid if-else/switch-case block
	map<string, string> optionValueMap = {
		{"zvmVersion", zvmVersion().name()},
		{"optimize", boolToString(optimize)},
		{"useABIEncoderV1", boolToString(useABIEncoderV1)},
		{"batch", to_string(selectedBatch + 1) + "/" + to_string(batches)},
		{"enforceGasTest", boolToString(enforceGasTest)},
		{"enforceGasTestMinValue", enforceGasTestMinValue.str()},
		{"disableSemanticTests", boolToString(disableSemanticTests)},
		{"disableSMT", boolToString(disableSMT)},
		{"showMessages", boolToString(showMessages)},
		{"showMetadata", boolToString(showMetadata)}
	};

	hyptestAssert(ranges::all_of(_selectedOptions, [&optionValueMap](string const& _option) { return optionValueMap.count(_option) > 0; }));

	vector<string> optionsWithValues = _selectedOptions |
		ranges::views::transform([&optionValueMap](string const& _option) { return _option + "=" + optionValueMap.at(_option); }) |
		ranges::to<vector>();

	return hyperion::util::joinHumanReadable(optionsWithValues);
}

void CommonOptions::printSelectedOptions(ostream& _stream, string const& _linePrefix, vector<string> const& _selectedOptions) const
{
	_stream << _linePrefix << "Run Settings: " << toString(_selectedOptions) << endl;
}

langutil::ZVMVersion CommonOptions::zvmVersion() const
{
	if (!zvmVersionString.empty())
	{
		auto version = langutil::ZVMVersion::fromString(zvmVersionString);
		if (!version)
			BOOST_THROW_EXCEPTION(std::runtime_error("Invalid ZVM version: " + zvmVersionString));
		return *version;
	}
	else
		return langutil::ZVMVersion();
}

CommonOptions const& CommonOptions::get()
{
	if (!m_singleton)
		BOOST_THROW_EXCEPTION(std::runtime_error("Options not yet constructed!"));

	return *m_singleton;
}

void CommonOptions::setSingleton(std::unique_ptr<CommonOptions const>&& _instance)
{
	m_singleton = std::move(_instance);
}

std::unique_ptr<CommonOptions const> CommonOptions::m_singleton = nullptr;

bool isValidSemanticTestPath(boost::filesystem::path const& _testPath)
{
	bool insideSemanticTests = false;
	fs::path testPathPrefix;
	for (auto const& element: _testPath)
	{
		testPathPrefix /= element;
		if (boost::ends_with(canonical(testPathPrefix).generic_string(), "/test/libhyperion/semanticTests"))
			insideSemanticTests = true;
		if (insideSemanticTests && boost::starts_with(element.string(), "_"))
			return false;
	}
	return true;
}

bool loadVMs(CommonOptions const& _options)
{
	if (_options.disableSemanticTests)
		return true;

	bool zvmSupported = hyperion::test::ZVMHost::checkVmPaths(_options.vmPaths);
	if (!_options.disableSemanticTests && !zvmSupported)
	{
		std::cerr << "Unable to find " << hyperion::test::zvmoneFilename;
		std::cerr << ". Please disable semantics tests with --no-semantic-tests or provide a path using --vm <path>." << std::endl;
		std::cerr << "You can download it at" << std::endl;
		std::cerr << hyperion::test::zvmoneDownloadLink << std::endl;
		return false;
	}
	return true;
}

}
