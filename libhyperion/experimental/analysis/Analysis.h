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

#include <vector>
#include <memory>

namespace hyperion::frontend
{
class SourceUnit;
}

namespace hyperion::langutil
{
class ErrorReporter;
}

namespace hyperion::frontend::experimental
{

class Analysis
{
public:
	Analysis(langutil::ErrorReporter& _errorReporter):
		m_errorReporter(_errorReporter)
	{}

	bool check(std::vector<std::shared_ptr<SourceUnit const>> const& _sourceUnits);

private:
	langutil::ErrorReporter& m_errorReporter;
};

}
