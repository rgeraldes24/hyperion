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
 * Component that verifies overloads, abstract contracts, function clashes and others
 * checks at contract or function level.
 */

#include <libhyperion/analysis/PostTypeContractLevelChecker.h>

#include <libhyperion/ast/AST.h>
#include <libhyputil/FunctionSelector.h>
#include <liblangutil/ErrorReporter.h>

using namespace hyperion;
using namespace hyperion::langutil;
using namespace hyperion::frontend;

bool PostTypeContractLevelChecker::check(SourceUnit const& _sourceUnit)
{
	bool noErrors = true;
	for (auto* contract: ASTNode::filteredNodes<ContractDefinition>(_sourceUnit.nodes()))
		if (!check(*contract))
			noErrors = false;
	return noErrors;
}

bool PostTypeContractLevelChecker::check(ContractDefinition const& _contract)
{
	hypAssert(
		_contract.annotation().creationCallGraph.set() &&
		_contract.annotation().deployedCallGraph.set(),
		""
	);

	std::map<uint32_t, std::map<std::string, SourceLocation>> errorHashes;
	for (ErrorDefinition const* error: _contract.interfaceErrors())
	{
		std::string signature = error->functionType(true)->externalSignature();
		uint32_t hash = util::selectorFromSignatureU32(signature);
		// Fail if there is a different signature for the same hash.
		if (!errorHashes[hash].empty() && !errorHashes[hash].count(signature))
		{
			SourceLocation& otherLocation = errorHashes[hash].begin()->second;
			m_errorReporter.typeError(
				4883_error,
				error->nameLocation(),
				SecondarySourceLocation{}.append("This error has a different signature but the same hash: ", otherLocation),
				"Error signature hash collision for " + error->functionType(true)->externalSignature()
			);
		}
		else
			errorHashes[hash][signature] = error->location();
	}

	return !Error::containsErrors(m_errorReporter.errors());
}
