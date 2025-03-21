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
/**
 * @author Christian <c@ethdev.com>
 * @date 2015
 * Parses and analyses the doc strings.
 * Stores the parsing results in the AST annotations and reports errors.
 */

#include <libhyperion/analysis/DocStringTagParser.h>

#include <libhyperion/ast/AST.h>
#include <libhyperion/parsing/DocStringParser.h>
#include <libhyperion/analysis/NameAndTypeResolver.h>
#include <liblangutil/ErrorReporter.h>
#include <liblangutil/Common.h>

#include <range/v3/algorithm/any_of.hpp>
#include <range/v3/view/filter.hpp>

#include <boost/algorithm/string.hpp>

#include <regex>
#include <string_view>

using namespace hyperion;
using namespace hyperion::langutil;
using namespace hyperion::frontend;

bool DocStringTagParser::parseDocStrings(SourceUnit const& _sourceUnit)
{
	auto errorWatcher = m_errorReporter.errorWatcher();
	_sourceUnit.accept(*this);
	return errorWatcher.ok();
}

bool DocStringTagParser::validateDocStringsUsingTypes(SourceUnit const& _sourceUnit)
{
	ErrorReporter::ErrorWatcher errorWatcher = m_errorReporter.errorWatcher();

	SimpleASTVisitor visitReturns(
		[](ASTNode const&) { return true; },
		[&](ASTNode const& _node)
		{
			if (auto const* annotation = dynamic_cast<StructurallyDocumentedAnnotation const*>(&_node.annotation()))
			{
				auto const& documentationNode = dynamic_cast<StructurallyDocumented const&>(_node);

				size_t returnTagsVisited = 0;

				for (auto const& [tagName, tagValue]: annotation->docTags)
					if (tagName == "return")
					{
						returnTagsVisited++;
						std::vector<std::string> returnParameterNames;

						if (auto const* varDecl = dynamic_cast<VariableDeclaration const*>(&_node))
						{
							if (!varDecl->isPublic())
								continue;

							// FunctionType() requires the DeclarationTypeChecker to have run.
							returnParameterNames = FunctionType(*varDecl).returnParameterNames();
						}
						else if (auto const* function = dynamic_cast<FunctionDefinition const*>(&_node))
							returnParameterNames = FunctionType(*function).returnParameterNames();
						else
							continue;

						std::string content = tagValue.content;
						std::string firstWord = content.substr(0, content.find_first_of(" \t"));

						if (returnTagsVisited > returnParameterNames.size())
							m_errorReporter.docstringParsingError(
								2604_error,
								documentationNode.documentation()->location(),
								"Documentation tag \"@" + tagName + " " + content + "\"" +
								" exceeds the number of return parameters."
							);
						else
						{
							std::string const& parameter = returnParameterNames.at(returnTagsVisited - 1);
							if (!parameter.empty() && parameter != firstWord)
								m_errorReporter.docstringParsingError(
									5856_error,
									documentationNode.documentation()->location(),
									"Documentation tag \"@" + tagName + " " + content + "\"" +
									" does not contain the name of its return parameter."
								);
						}
					}
			}
	});

	_sourceUnit.accept(visitReturns);
	return errorWatcher.ok();
}

bool DocStringTagParser::visit(ContractDefinition const& _contract)
{
	static std::set<std::string> const validTags = std::set<std::string>{"author", "title", "dev", "notice"};
	parseDocStrings(_contract, _contract.annotation(), validTags, "contracts");

	return true;
}

bool DocStringTagParser::visit(FunctionDefinition const& _function)
{
	if (_function.isConstructor())
		handleConstructor(_function, _function, _function.annotation());
	else
		handleCallable(_function, _function, _function.annotation());
	return true;
}

bool DocStringTagParser::visit(VariableDeclaration const& _variable)
{
	if (_variable.isStateVariable())
	{
		if (_variable.isPublic())
			parseDocStrings(_variable, _variable.annotation(), {"dev", "notice", "return", "inheritdoc"}, "public state variables");
		else
			parseDocStrings(_variable, _variable.annotation(), {"dev", "notice", "inheritdoc"}, "non-public state variables");
	}
	else if (_variable.isFileLevelVariable())
		parseDocStrings(_variable, _variable.annotation(), {"dev"}, "file-level variables");
	return false;
}

bool DocStringTagParser::visit(ModifierDefinition const& _modifier)
{
	handleCallable(_modifier, _modifier, _modifier.annotation());

	return true;
}

bool DocStringTagParser::visit(EventDefinition const& _event)
{
	handleCallable(_event, _event, _event.annotation());

	return true;
}

bool DocStringTagParser::visit(ErrorDefinition const& _error)
{
	handleCallable(_error, _error, _error.annotation());

	return true;
}

bool DocStringTagParser::visit(InlineAssembly const& _assembly)
{
	if (!_assembly.documentation())
		return true;
	StructuredDocumentation documentation{-1, _assembly.location(), _assembly.documentation()};
	ErrorList errors;
	ErrorReporter errorReporter{errors};
	auto docTags = DocStringParser{documentation, errorReporter}.parse();

	if (!errors.empty())
	{
		SecondarySourceLocation ssl;
		for (auto const& error: errors)
			if (error->comment())
				ssl.append(
					*error->comment(),
					_assembly.location()
				);
		m_errorReporter.warning(
			7828_error,
			_assembly.location(),
			"Inline assembly has invalid NatSpec documentation.",
			ssl
		);
	}

	for (auto const& [tagName, tagValue]: docTags)
	{
		if (tagName == "hyperion")
		{
			std::vector<std::string> values;
			boost::split(values, tagValue.content, isWhiteSpace);

			std::set<std::string> valuesSeen;
			std::set<std::string> duplicates;
			for (auto const& value: values | ranges::views::filter(not_fn(&std::string::empty)))
				if (valuesSeen.insert(value).second)
				{
					if (value == "memory-safe-assembly")
					{
						if (_assembly.annotation().markedMemorySafe)
							m_errorReporter.warning(
								8544_error,
								_assembly.location(),
								"Inline assembly marked as memory safe using both a NatSpec tag and an assembly flag. "
								"If you are not concerned with backwards compatibility, only use the assembly flag, "
								"otherwise only use the NatSpec tag."
							);
						_assembly.annotation().markedMemorySafe = true;
					}
					else
						m_errorReporter.warning(
							8787_error,
							_assembly.location(),
							"Unexpected value for @hyperion tag in inline assembly: " + value
						);
				}
				else if (duplicates.insert(value).second)
					m_errorReporter.warning(
						4377_error,
						_assembly.location(),
						"Value for @hyperion tag in inline assembly specified multiple times: " + value
					);
		}
		else
			m_errorReporter.warning(
				6269_error,
				_assembly.location(),
				"Unexpected NatSpec tag \"" + tagName + "\" with value \"" + tagValue.content + "\" in inline assembly."
			);
	}

	return true;
}

void DocStringTagParser::checkParameters(
	CallableDeclaration const& _callable,
	StructurallyDocumented const& _node,
	StructurallyDocumentedAnnotation& _annotation
)
{
	std::set<std::string> validParams;
	for (auto const& p: _callable.parameters())
		validParams.insert(p->name());
	if (_callable.returnParameterList())
		for (auto const& p: _callable.returnParameterList()->parameters())
			validParams.insert(p->name());
	auto paramRange = _annotation.docTags.equal_range("param");
	for (auto i = paramRange.first; i != paramRange.second; ++i)
		if (!validParams.count(i->second.paramName))
			m_errorReporter.docstringParsingError(
				3881_error,
				_node.documentation()->location(),
				"Documented parameter \"" +
				i->second.paramName +
				"\" not found in the parameter list of the function."
			);
}

void DocStringTagParser::handleConstructor(
	CallableDeclaration const& _callable,
	StructurallyDocumented const& _node,
	StructurallyDocumentedAnnotation& _annotation
)
{
	static std::set<std::string> const validTags = std::set<std::string>{"author", "dev", "notice", "param"};
	parseDocStrings(_node, _annotation, validTags, "constructor");
	checkParameters(_callable, _node, _annotation);
}

void DocStringTagParser::handleCallable(
	CallableDeclaration const& _callable,
	StructurallyDocumented const& _node,
	StructurallyDocumentedAnnotation& _annotation
)
{
	static std::set<std::string> const validEventTags = std::set<std::string>{"dev", "notice", "return", "param"};
	static std::set<std::string> const validErrorTags = std::set<std::string>{"dev", "notice", "param"};
	static std::set<std::string> const validModifierTags = std::set<std::string>{"dev", "notice", "param", "inheritdoc"};
	static std::set<std::string> const validTags = std::set<std::string>{"dev", "notice", "return", "param", "inheritdoc"};

	if (dynamic_cast<EventDefinition const*>(&_callable))
		parseDocStrings(_node, _annotation, validEventTags, "events");
	else if (dynamic_cast<ErrorDefinition const*>(&_callable))
		parseDocStrings(_node, _annotation, validErrorTags, "errors");
	else if (dynamic_cast<ModifierDefinition const*>(&_callable))
		parseDocStrings(_node, _annotation, validModifierTags, "modifiers");
	else
		parseDocStrings(_node, _annotation, validTags, "functions");

	checkParameters(_callable, _node, _annotation);
}

void DocStringTagParser::parseDocStrings(
	StructurallyDocumented const& _node,
	StructurallyDocumentedAnnotation& _annotation,
	std::set<std::string> const& _validTags,
	std::string const& _nodeName
)
{
	if (!_node.documentation())
		return;

	_annotation.docTags = DocStringParser{*_node.documentation(), m_errorReporter}.parse();

	for (auto const& [tagName, tagValue]: _annotation.docTags)
	{
		std::string_view static constexpr customPrefix("custom:");
		if (tagName == "custom" || tagName == "custom:")
			m_errorReporter.docstringParsingError(
				6564_error,
				_node.documentation()->location(),
				"Custom documentation tag must contain a chosen name, i.e. @custom:mytag."
			);
		else if (boost::starts_with(tagName, customPrefix) && tagName.size() > customPrefix.size())
		{
			std::regex static const customRegex("^custom:[a-z][a-z-]*$");
			if (!regex_match(tagName, customRegex))
				m_errorReporter.docstringParsingError(
					2968_error,
					_node.documentation()->location(),
					"Invalid character in custom tag @" + tagName + ". Only lowercase letters and \"-\" are permitted."
				);
			continue;
		}
		else if (!_validTags.count(tagName))
			m_errorReporter.docstringParsingError(
				6546_error,
				_node.documentation()->location(),
				"Documentation tag @" + tagName + " not valid for " + _nodeName + "."
			);
	}
}

