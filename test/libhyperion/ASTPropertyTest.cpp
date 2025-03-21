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

#include <test/libhyperion/ASTPropertyTest.h>
#include <test/Common.h>

#include <libhyperion/ast/ASTJsonExporter.h>
#include <libhyperion/interface/CompilerStack.h>

#include <liblangutil/Common.h>
#include <liblangutil/SourceReferenceFormatter.h>
#include <libhyputil/JSON.h>

#include <boost/algorithm/string.hpp>
#include <boost/throw_exception.hpp>

#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/split.hpp>

#include <queue>

using namespace hyperion::util;
using namespace hyperion::langutil;
using namespace hyperion::frontend;
using namespace hyperion::frontend::test;
using namespace hyperion;
using namespace std::string_literals;

ASTPropertyTest::ASTPropertyTest(std::string const& _filename):
	TestCase(_filename)
{
	if (!boost::algorithm::ends_with(_filename, ".hyp"))
		BOOST_THROW_EXCEPTION(std::runtime_error("Not a Hyperion file: \"" + _filename + "\"."));

	m_source = m_reader.source();
	readExpectations();
	hyptestAssert(m_tests.size() > 0, "No tests specified in " + _filename);
}

std::string ASTPropertyTest::formatExpectations(bool _obtainedResult)
{
	std::string expectations;
	for (std::string const& testId: m_testOrder)
	{
		hyptestAssert(m_tests.count(testId) > 0);
		expectations +=
			testId +
			": " +
			(_obtainedResult ? m_tests[testId].obtainedValue : m_tests[testId].expectedValue)
			+ "\n";
	}
	return expectations;
}

std::vector<StringPair> ASTPropertyTest::readKeyValuePairs(std::string const& _input)
{
	std::vector<StringPair> result;
	for (std::string line: _input | ranges::views::split('\n') | ranges::to<std::vector<std::string>>)
	{
		boost::trim(line);
		if (line.empty())
			continue;

		hyptestAssert(
			ranges::all_of(line, [](char c) { return isprint(c); }),
			"Non-printable character(s) found in property test: " + line
		);

		auto colonPosition = line.find_first_of(':');
		hyptestAssert(colonPosition != std::string::npos, "Property test is missing a colon: " + line);

		StringPair pair{
			boost::trim_copy(line.substr(0, colonPosition)),
			boost::trim_copy(line.substr(colonPosition + 1))
		};
		hyptestAssert(!std::get<0>(pair).empty() != false, "Empty key in property test: " + line);
		hyptestAssert(!std::get<1>(pair).empty() != false, "Empty value in property test: " + line);

		result.push_back(pair);
	}
	return result;
}

void ASTPropertyTest::readExpectations()
{
	for (auto const& [testId, testExpectation]: readKeyValuePairs(m_reader.simpleExpectations()))
	{
		hyptestAssert(m_tests.count(testId) == 0, "More than one expectation for test \"" + testId + "\"");
		m_tests.emplace(testId, Test{"", testExpectation, ""});
		m_testOrder.push_back(testId);
	}
	m_expectation = formatExpectations(false /* _obtainedResult */);
}

void ASTPropertyTest::extractTestsFromAST(Json::Value const& _astJson)
{
	std::queue<Json::Value> nodesToVisit;
	nodesToVisit.push(_astJson);

	while (!nodesToVisit.empty())
	{
		Json::Value& node = nodesToVisit.front();

		if (node.isArray())
			for (auto&& member: node)
				nodesToVisit.push(member);
		else if (node.isObject())
			for (std::string const& memberName: node.getMemberNames())
			{
				if (memberName != "documentation")
				{
					nodesToVisit.push(node[memberName]);
					continue;
				}

				std::string nodeDocstring = node["documentation"].isObject() ?
					node["documentation"]["text"].asString() :
					node["documentation"].asString();
				hyptestAssert(!nodeDocstring.empty());

				std::vector<StringPair> pairs = readKeyValuePairs(nodeDocstring);
				if (pairs.empty())
					continue;

				for (auto const& [testId, testedProperty]: pairs)
				{
					hyptestAssert(
						m_tests.count(testId) > 0,
						"Test \"" + testId + "\" does not have a corresponding expected value."
					);
					hyptestAssert(
						m_tests[testId].property.empty(),
						"Test \"" + testId + "\" was already defined before."
					);
					m_tests[testId].property = testedProperty;

					hyptestAssert(node.isMember("nodeType"));
					std::optional<Json::Value> propertyNode = jsonValueByPath(node, testedProperty);
					hyptestAssert(
						propertyNode.has_value(),
						node["nodeType"].asString() + " node does not have a property named \""s + testedProperty + "\""
					);
					hyptestAssert(
						!propertyNode->isObject() && !propertyNode->isArray(),
						"Property \"" + testedProperty + "\" is an object or an array."
					);
					m_tests[testId].obtainedValue = propertyNode->asString();
				}
			}

		nodesToVisit.pop();
	}

	auto firstTestWithoutProperty = ranges::find_if(
		m_tests,
		[&](auto const& _testCase) { return _testCase.second.property.empty(); }
	);
	hyptestAssert(
		firstTestWithoutProperty == ranges::end(m_tests),
		"AST property not defined for test \"" + firstTestWithoutProperty->first + "\""
	);

	m_obtainedResult = formatExpectations(true /* _obtainedResult */);
}

TestCase::TestResult ASTPropertyTest::run(std::ostream& _stream, std::string const& _linePrefix, bool const _formatted)
{
	CompilerStack compiler;

	compiler.setSources({{
		"A",
		"pragma hyperion >=0.0;\n// SPDX-License-Identifier: GPL-3.0\n" + m_source
	}});
	compiler.setZVMVersion(hyperion::test::CommonOptions::get().zvmVersion());
	compiler.setOptimiserSettings(hyperion::test::CommonOptions::get().optimize);
	if (!compiler.parseAndAnalyze())
		BOOST_THROW_EXCEPTION(std::runtime_error(
			"Parsing contract failed" +
			SourceReferenceFormatter::formatErrorInformation(compiler.errors(), compiler, _formatted)
		));

	Json::Value astJson = ASTJsonExporter(compiler.state()).toJson(compiler.ast("A"));
	hyptestAssert(astJson);

	extractTestsFromAST(astJson);

	return checkResult(_stream, _linePrefix, _formatted);
}
