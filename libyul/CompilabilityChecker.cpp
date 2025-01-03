/*(
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
 * Component that checks whether all variables are reachable on the stack.
 */

#include <libyul/CompilabilityChecker.h>

#include <libyul/AsmAnalysis.h>
#include <libyul/AsmAnalysisInfo.h>

#include <libyul/backends/zvm/ZVMCodeTransform.h>
#include <libyul/backends/zvm/NoOutputAssembly.h>

using namespace hyperion;
using namespace hyperion::yul;
using namespace hyperion::util;

CompilabilityChecker::CompilabilityChecker(
	Dialect const& _dialect,
	Object const& _object,
	bool _optimizeStackAllocation
)
{
	if (auto const* zvmDialect = dynamic_cast<ZVMDialect const*>(&_dialect))
	{
		NoOutputZVMDialect noOutputDialect(*zvmDialect);

		yul::AsmAnalysisInfo analysisInfo =
			yul::AsmAnalyzer::analyzeStrictAssertCorrect(noOutputDialect, _object);

		BuiltinContext builtinContext;
		builtinContext.currentObject = &_object;
		if (!_object.name.empty())
			builtinContext.subIDs[_object.name] = 1;
		for (auto const& subNode: _object.subObjects)
			builtinContext.subIDs[subNode->name] = 1;
		NoOutputAssembly assembly{zvmDialect->zvmVersion()};
		CodeTransform transform(
			assembly,
			analysisInfo,
			*_object.code,
			noOutputDialect,
			builtinContext,
			_optimizeStackAllocation
		);
		transform(*_object.code);

		for (StackTooDeepError const& error: transform.stackErrors())
		{
			auto& unreachables = unreachableVariables[error.functionName];
			if (!util::contains(unreachables, error.variable))
				unreachables.emplace_back(error.variable);
			int& deficit = stackDeficit[error.functionName];
			deficit = std::max(error.depth, deficit);
		}
	}
}
