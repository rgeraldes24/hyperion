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

#include <libsmtutil/CVC4Interface.h>

#include <libhyputil/CommonIO.h>
#include <libhyputil/Exceptions.h>

#include <cvc4/util/bitvector.h>

using namespace hyperion;
using namespace hyperion::util;
using namespace hyperion::smtutil;

CVC4Interface::CVC4Interface(std::optional<unsigned> _queryTimeout):
	SolverInterface(_queryTimeout),
	m_solver(&m_context)
{
	reset();
}

void CVC4Interface::reset()
{
	m_variables.clear();
	m_solver.reset();
	m_solver.setOption("produce-models", true);
	if (m_queryTimeout)
		m_solver.setTimeLimit(*m_queryTimeout);
	else
		m_solver.setResourceLimit(resourceLimit);
}

void CVC4Interface::push()
{
	m_solver.push();
}

void CVC4Interface::pop()
{
	m_solver.pop();
}

void CVC4Interface::declareVariable(std::string const& _name, SortPointer const& _sort)
{
	smtAssert(_sort, "");
	m_variables[_name] = m_context.mkVar(_name.c_str(), cvc4Sort(*_sort));
}

void CVC4Interface::addAssertion(Expression const& _expr)
{
	try
	{
		m_solver.assertFormula(toCVC4Expr(_expr));
	}
	catch (CVC4::TypeCheckingException const& _e)
	{
		smtAssert(false, _e.what());
	}
	catch (CVC4::LogicException const& _e)
	{
		smtAssert(false, _e.what());
	}
	catch (CVC4::UnsafeInterruptException const& _e)
	{
		smtAssert(false, _e.what());
	}
	catch (CVC4::Exception const& _e)
	{
		smtAssert(false, _e.what());
	}
}

std::pair<CheckResult, std::vector<std::string>> CVC4Interface::check(std::vector<Expression> const& _expressionsToEvaluate)
{
	CheckResult result;
	std::vector<std::string> values;
	try
	{
		switch (m_solver.checkSat().isSat())
		{
		case CVC4::Result::SAT:
			result = CheckResult::SATISFIABLE;
			break;
		case CVC4::Result::UNSAT:
			result = CheckResult::UNSATISFIABLE;
			break;
		case CVC4::Result::SAT_UNKNOWN:
			result = CheckResult::UNKNOWN;
			break;
		default:
			smtAssert(false, "");
		}

		if (result == CheckResult::SATISFIABLE && !_expressionsToEvaluate.empty())
		{
			for (Expression const& e: _expressionsToEvaluate)
				values.push_back(toString(m_solver.getValue(toCVC4Expr(e))));
		}
	}
	catch (CVC4::Exception const&)
	{
		result = CheckResult::ERROR;
		values.clear();
	}

	return std::make_pair(result, values);
}

CVC4::Expr CVC4Interface::toCVC4Expr(Expression const& _expr)
{
	// Variable
	if (_expr.arguments.empty() && m_variables.count(_expr.name))
		return m_variables.at(_expr.name);

	std::vector<CVC4::Expr> arguments;
	for (auto const& arg: _expr.arguments)
		arguments.push_back(toCVC4Expr(arg));

	try
	{
		std::string const& n = _expr.name;
		// Function application
		if (!arguments.empty() && m_variables.count(_expr.name))
			return m_context.mkExpr(CVC4::kind::APPLY_UF, m_variables.at(n), arguments);
		// Literal
		else if (arguments.empty())
		{
			if (n == "true")
				return m_context.mkConst(true);
			else if (n == "false")
				return m_context.mkConst(false);
			else if (auto sortSort = std::dynamic_pointer_cast<SortSort>(_expr.sort))
				return m_context.mkVar(n, cvc4Sort(*sortSort->inner));
			else
				try
				{
					return m_context.mkConst(CVC4::Rational(n));
				}
				catch (CVC4::TypeCheckingException const& _e)
				{
					smtAssert(false, _e.what());
				}
				catch (CVC4::Exception const& _e)
				{
					smtAssert(false, _e.what());
				}
		}

		smtAssert(_expr.hasCorrectArity(), "");
		if (n == "ite")
			return arguments[0].iteExpr(arguments[1], arguments[2]);
		else if (n == "not")
			return arguments[0].notExpr();
		else if (n == "and")
			return arguments[0].andExpr(arguments[1]);
		else if (n == "or")
			return arguments[0].orExpr(arguments[1]);
		else if (n == "=>")
			return m_context.mkExpr(CVC4::kind::IMPLIES, arguments[0], arguments[1]);
		else if (n == "=")
			return m_context.mkExpr(CVC4::kind::EQUAL, arguments[0], arguments[1]);
		else if (n == "<")
			return m_context.mkExpr(CVC4::kind::LT, arguments[0], arguments[1]);
		else if (n == "<=")
			return m_context.mkExpr(CVC4::kind::LEQ, arguments[0], arguments[1]);
		else if (n == ">")
			return m_context.mkExpr(CVC4::kind::GT, arguments[0], arguments[1]);
		else if (n == ">=")
			return m_context.mkExpr(CVC4::kind::GEQ, arguments[0], arguments[1]);
		else if (n == "+")
			return m_context.mkExpr(CVC4::kind::PLUS, arguments[0], arguments[1]);
		else if (n == "-")
			return m_context.mkExpr(CVC4::kind::MINUS, arguments[0], arguments[1]);
		else if (n == "*")
			return m_context.mkExpr(CVC4::kind::MULT, arguments[0], arguments[1]);
		else if (n == "div")
			return m_context.mkExpr(CVC4::kind::INTS_DIVISION_TOTAL, arguments[0], arguments[1]);
		else if (n == "mod")
			return m_context.mkExpr(CVC4::kind::INTS_MODULUS, arguments[0], arguments[1]);
		else if (n == "bvnot")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_NOT, arguments[0]);
		else if (n == "bvand")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_AND, arguments[0], arguments[1]);
		else if (n == "bvor")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_OR, arguments[0], arguments[1]);
		else if (n == "bvxor")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_XOR, arguments[0], arguments[1]);
		else if (n == "bvshl")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_SHL, arguments[0], arguments[1]);
		else if (n == "bvlshr")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_LSHR, arguments[0], arguments[1]);
		else if (n == "bvashr")
			return m_context.mkExpr(CVC4::kind::BITVECTOR_ASHR, arguments[0], arguments[1]);
		else if (n == "int2bv")
		{
			size_t size = std::stoul(_expr.arguments[1].name);
			auto i2bvOp = m_context.mkConst(CVC4::IntToBitVector(static_cast<unsigned>(size)));
			// CVC4 treats all BVs as unsigned, so we need to manually apply 2's complement if needed.
			return m_context.mkExpr(
				CVC4::kind::ITE,
				m_context.mkExpr(CVC4::kind::GEQ, arguments[0], m_context.mkConst(CVC4::Rational(0))),
				m_context.mkExpr(CVC4::kind::INT_TO_BITVECTOR, i2bvOp, arguments[0]),
				m_context.mkExpr(
					CVC4::kind::BITVECTOR_NEG,
					m_context.mkExpr(CVC4::kind::INT_TO_BITVECTOR, i2bvOp, m_context.mkExpr(CVC4::kind::UMINUS, arguments[0]))
				)
			);
		}
		else if (n == "bv2int")
		{
			auto intSort = std::dynamic_pointer_cast<IntSort>(_expr.sort);
			smtAssert(intSort, "");
			auto nat = m_context.mkExpr(CVC4::kind::BITVECTOR_TO_NAT, arguments[0]);
			if (!intSort->isSigned)
				return nat;

			auto type = arguments[0].getType();
			smtAssert(type.isBitVector(), "");
			auto size = CVC4::BitVectorType(type).getSize();
			// CVC4 treats all BVs as unsigned, so we need to manually apply 2's complement if needed.
			auto extractOp = m_context.mkConst(CVC4::BitVectorExtract(size - 1, size - 1));
			return m_context.mkExpr(CVC4::kind::ITE,
				m_context.mkExpr(
					CVC4::kind::EQUAL,
					m_context.mkExpr(CVC4::kind::BITVECTOR_EXTRACT, extractOp, arguments[0]),
					m_context.mkConst(CVC4::BitVector(1, uint64_t{0}))
				),
				nat,
				m_context.mkExpr(
					CVC4::kind::UMINUS,
					m_context.mkExpr(CVC4::kind::BITVECTOR_TO_NAT, m_context.mkExpr(CVC4::kind::BITVECTOR_NEG, arguments[0]))
				)
			);
		}
		else if (n == "select")
			return m_context.mkExpr(CVC4::kind::SELECT, arguments[0], arguments[1]);
		else if (n == "store")
			return m_context.mkExpr(CVC4::kind::STORE, arguments[0], arguments[1], arguments[2]);
		else if (n == "const_array")
		{
			std::shared_ptr<SortSort> sortSort = std::dynamic_pointer_cast<SortSort>(_expr.arguments[0].sort);
			smtAssert(sortSort, "");
			return m_context.mkConst(CVC4::ArrayStoreAll(cvc4Sort(*sortSort->inner), arguments[1]));
		}
		else if (n == "tuple_get")
		{
			std::shared_ptr<TupleSort> tupleSort = std::dynamic_pointer_cast<TupleSort>(_expr.arguments[0].sort);
			smtAssert(tupleSort, "");
			CVC4::DatatypeType tt = m_context.mkTupleType(cvc4Sort(tupleSort->components));
			CVC4::Datatype const& dt = tt.getDatatype();
			size_t index = std::stoul(_expr.arguments[1].name);
			CVC4::Expr s = dt[0][index].getSelector();
			return m_context.mkExpr(CVC4::kind::APPLY_SELECTOR, s, arguments[0]);
		}
		else if (n == "tuple_constructor")
		{
			std::shared_ptr<TupleSort> tupleSort = std::dynamic_pointer_cast<TupleSort>(_expr.sort);
			smtAssert(tupleSort, "");
			CVC4::DatatypeType tt = m_context.mkTupleType(cvc4Sort(tupleSort->components));
			CVC4::Datatype const& dt = tt.getDatatype();
			CVC4::Expr c = dt[0].getConstructor();
			return m_context.mkExpr(CVC4::kind::APPLY_CONSTRUCTOR, c, arguments);
		}

		smtAssert(false);
	}
	catch (CVC4::TypeCheckingException const& _e)
	{
		smtAssert(false, _e.what());
	}
	catch (CVC4::Exception const& _e)
	{
		smtAssert(false, _e.what());
	}

	smtAssert(false);

	// FIXME: Workaround for spurious GCC 12.1 warning (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105794)
	util::unreachable();
}

CVC4::Type CVC4Interface::cvc4Sort(Sort const& _sort)
{
	switch (_sort.kind)
	{
	case Kind::Bool:
		return m_context.booleanType();
	case Kind::Int:
		return m_context.integerType();
	case Kind::BitVector:
		return m_context.mkBitVectorType(dynamic_cast<BitVectorSort const&>(_sort).size);
	case Kind::Function:
	{
		FunctionSort const& fSort = dynamic_cast<FunctionSort const&>(_sort);
		return m_context.mkFunctionType(cvc4Sort(fSort.domain), cvc4Sort(*fSort.codomain));
	}
	case Kind::Array:
	{
		auto const& arraySort = dynamic_cast<ArraySort const&>(_sort);
		return m_context.mkArrayType(cvc4Sort(*arraySort.domain), cvc4Sort(*arraySort.range));
	}
	case Kind::Tuple:
	{
		auto const& tupleSort = dynamic_cast<TupleSort const&>(_sort);
		return m_context.mkTupleType(cvc4Sort(tupleSort.components));
	}
	default:
		break;
	}
	smtAssert(false, "");
	// Cannot be reached.
	return m_context.integerType();
}

std::vector<CVC4::Type> CVC4Interface::cvc4Sort(std::vector<SortPointer> const& _sorts)
{
	std::vector<CVC4::Type> cvc4Sorts;
	for (auto const& _sort: _sorts)
		cvc4Sorts.push_back(cvc4Sort(*_sort));
	return cvc4Sorts;
}
