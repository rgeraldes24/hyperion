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
#include <libyul/optimiser/SSAReverser.h>
#include <libyul/optimiser/Metrics.h>
#include <libyul/AST.h>
#include <libhyputil/CommonData.h>

#include <variant>

using namespace hyperion;
using namespace hyperion::yul;

void SSAReverser::run(OptimiserStepContext&, Block& _block)
{
	AssignmentCounter assignmentCounter;
	assignmentCounter(_block);
	SSAReverser{assignmentCounter}(_block);
}

void SSAReverser::operator()(Block& _block)
{
	walkVector(_block.statements);
	util::iterateReplacingWindow<2>(
		_block.statements,
		[&](Statement& _stmt1, Statement& _stmt2) -> std::optional<std::vector<Statement>>
		{
			auto* varDecl = std::get_if<VariableDeclaration>(&_stmt1);

			if (!varDecl || varDecl->variables.size() != 1 || !varDecl->value)
				return {};

			// Replaces
			//   let a_1 := E
			//   a := a_1
			// with
			//   a := E
			//   let a_1 := a
			if (auto* assignment = std::get_if<Assignment>(&_stmt2))
			{
				auto* identifier = std::get_if<Identifier>(assignment->value.get());
				if (
					assignment->variableNames.size() == 1 &&
					identifier &&
					identifier->name == varDecl->variables.front().name
				)
				{
					// in the special case a == a_1, just remove the assignment
					if (assignment->variableNames.front().name == identifier->name)
						return util::make_vector<Statement>(std::move(_stmt1));
					else
						return util::make_vector<Statement>(
							Assignment{
								std::move(assignment->debugData),
								assignment->variableNames,
								std::move(varDecl->value)
							},
							VariableDeclaration{
								std::move(varDecl->debugData),
								std::move(varDecl->variables),
								std::make_unique<Expression>(assignment->variableNames.front())
							}
						);
				}
			}
			// Replaces
			//   let a_1 := E
			//   let a := a_1
			// with
			//   let a := E
			//   let a_1 := a
			else if (auto* varDecl2 = std::get_if<VariableDeclaration>(&_stmt2))
			{
				auto* identifier = std::get_if<Identifier>(varDecl2->value.get());
				if (
					varDecl2->variables.size() == 1 &&
					identifier &&
					identifier->name == varDecl->variables.front().name && (
						m_assignmentCounter.assignmentCount(varDecl2->variables.front().name) >
						m_assignmentCounter.assignmentCount(varDecl->variables.front().name)
					)
				)
				{
					auto varIdentifier2 = std::make_unique<Expression>(Identifier{
						varDecl2->variables.front().debugData,
						varDecl2->variables.front().name
					});
					return util::make_vector<Statement>(
						VariableDeclaration{
							std::move(varDecl2->debugData),
							std::move(varDecl2->variables),
							std::move(varDecl->value)
						},
						VariableDeclaration{
							std::move(varDecl->debugData),
							std::move(varDecl->variables),
							std::move(varIdentifier2)
						}
					);
				}
			}

			return {};
		}
	);
}
