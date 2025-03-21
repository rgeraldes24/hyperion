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
 * Optimiser component that changes the code so that it consists of a block starting with
 * a single block followed only by function definitions and with no functions defined
 * anywhere else.
 */

#include <libyul/optimiser/FunctionHoister.h>
#include <libyul/optimiser/OptimizerUtilities.h>
#include <libyul/AST.h>

#include <libhyputil/CommonData.h>

using namespace hyperion;
using namespace hyperion::yul;

void FunctionHoister::operator()(Block& _block)
{
	bool topLevel = m_isTopLevel;
	m_isTopLevel = false;
	for (auto&& statement: _block.statements)
	{
		std::visit(*this, statement);
		if (std::holds_alternative<FunctionDefinition>(statement))
		{
			m_functions.emplace_back(std::move(statement));
			statement = Block{_block.debugData, {}};
		}
	}
	removeEmptyBlocks(_block);
	if (topLevel)
		_block.statements += std::move(m_functions);
}
