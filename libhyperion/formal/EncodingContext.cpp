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

#include <libhyperion/formal/EncodingContext.h>

#include <libhyperion/formal/SymbolicTypes.h>

using namespace hyperion;
using namespace hyperion::util;
using namespace hyperion::frontend::smt;

EncodingContext::EncodingContext():
	m_state(*this)
{
}

void EncodingContext::reset()
{
	resetAllVariables();
	m_expressions.clear();
	m_globalContext.clear();
	m_state.reset();
	m_assertions.clear();
}

void EncodingContext::resetUniqueId()
{
	m_nextUniqueId = 0;
}

unsigned EncodingContext::newUniqueId()
{
	return m_nextUniqueId++;
}

/// Variables.

std::shared_ptr<SymbolicVariable> EncodingContext::variable(frontend::VariableDeclaration const& _varDecl)
{
	hypAssert(knownVariable(_varDecl), "");
	return m_variables[&_varDecl];
}

bool EncodingContext::createVariable(frontend::VariableDeclaration const& _varDecl)
{
	hypAssert(!knownVariable(_varDecl), "");
	auto const& type = _varDecl.type();
	auto result = newSymbolicVariable(*type, _varDecl.name() + "_" + std::to_string(_varDecl.id()), *this);
	m_variables.emplace(&_varDecl, result.second);
	return result.first;
}

bool EncodingContext::knownVariable(frontend::VariableDeclaration const& _varDecl)
{
	return m_variables.count(&_varDecl);
}

void EncodingContext::resetVariable(frontend::VariableDeclaration const& _variable)
{
	newValue(_variable);
	setUnknownValue(_variable);
}

void EncodingContext::resetVariables(std::set<frontend::VariableDeclaration const*> const& _variables)
{
	for (auto const* decl: _variables)
		resetVariable(*decl);
}

void EncodingContext::resetVariables(std::function<bool(frontend::VariableDeclaration const&)> const& _filter)
{
	for_each(begin(m_variables), end(m_variables), [&](auto _variable)
	{
		if (_filter(*_variable.first))
			this->resetVariable(*_variable.first);
	});
}

void EncodingContext::resetAllVariables()
{
	resetVariables([&](frontend::VariableDeclaration const&) { return true; });
}

smtutil::Expression EncodingContext::newValue(frontend::VariableDeclaration const& _decl)
{
	hypAssert(knownVariable(_decl), "");
	return m_variables.at(&_decl)->increaseIndex();
}

void EncodingContext::setZeroValue(frontend::VariableDeclaration const& _decl)
{
	hypAssert(knownVariable(_decl), "");
	setZeroValue(*m_variables.at(&_decl));
}

void EncodingContext::setZeroValue(SymbolicVariable& _variable)
{
	setSymbolicZeroValue(_variable, *this);
}

void EncodingContext::setUnknownValue(frontend::VariableDeclaration const& _decl)
{
	hypAssert(knownVariable(_decl), "");
	setUnknownValue(*m_variables.at(&_decl));
}

void EncodingContext::setUnknownValue(SymbolicVariable& _variable)
{
	setSymbolicUnknownValue(_variable, *this);
}

/// Expressions

std::shared_ptr<SymbolicVariable> EncodingContext::expression(frontend::Expression const& _e)
{
	if (!knownExpression(_e))
		createExpression(_e);
	return m_expressions.at(&_e);
}

bool EncodingContext::createExpression(frontend::Expression const& _e, std::shared_ptr<SymbolicVariable> _symbVar)
{
	hypAssert(_e.annotation().type, "");
	if (knownExpression(_e))
	{
		expression(_e)->increaseIndex();
		return false;
	}
	else if (_symbVar)
	{
		m_expressions.emplace(&_e, _symbVar);
		return false;
	}
	else
	{
		auto result = newSymbolicVariable(*_e.annotation().type, "expr_" + std::to_string(_e.id()), *this);
		m_expressions.emplace(&_e, result.second);
		return result.first;
	}
}

bool EncodingContext::knownExpression(frontend::Expression const& _e) const
{
	return m_expressions.count(&_e);
}

/// Global variables and functions.

std::shared_ptr<SymbolicVariable> EncodingContext::globalSymbol(std::string const& _name)
{
	hypAssert(knownGlobalSymbol(_name), "");
	return m_globalContext.at(_name);
}

bool EncodingContext::createGlobalSymbol(std::string const& _name, frontend::Expression const& _expr)
{
	hypAssert(!knownGlobalSymbol(_name), "");
	auto result = newSymbolicVariable(*_expr.annotation().type, _name, *this);
	m_globalContext.emplace(_name, result.second);
	setUnknownValue(*result.second);
	return result.first;
}

bool EncodingContext::knownGlobalSymbol(std::string const& _var) const
{
	return m_globalContext.count(_var);
}

/// Solver.

smtutil::Expression EncodingContext::assertions()
{
	if (m_assertions.empty())
		return smtutil::Expression(true);

	return m_assertions.back();
}

void EncodingContext::pushSolver()
{
	if (m_accumulateAssertions)
		m_assertions.push_back(assertions());
	else
		m_assertions.emplace_back(true);
}

void EncodingContext::popSolver()
{
	hypAssert(!m_assertions.empty(), "");
	m_assertions.pop_back();
}

void EncodingContext::addAssertion(smtutil::Expression const& _expr)
{
	if (m_assertions.empty())
		m_assertions.push_back(_expr);
	else
		m_assertions.back() = _expr && std::move(m_assertions.back());
}
