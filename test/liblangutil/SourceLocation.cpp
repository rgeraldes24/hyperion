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
 * @author Yoichi Hirai <yoichi@ethereum.org>
 * @date 2016
 * Unit tests for the SourceLocation class.
 */

#include <liblangutil/SourceLocation.h>

#include <test/Common.h>

#include <boost/test/unit_test.hpp>

namespace hyperion::langutil::test
{

BOOST_AUTO_TEST_SUITE(SourceLocationTest)

BOOST_AUTO_TEST_CASE(test_fail)
{
	auto const source = std::make_shared<std::string>("source");
	auto const sourceA = std::make_shared<std::string>("sourceA");
	auto const sourceB = std::make_shared<std::string>("sourceB");

	BOOST_CHECK(SourceLocation{} == SourceLocation{});
	BOOST_CHECK((SourceLocation{0, 3, sourceA} != SourceLocation{0, 3, sourceB}));
	BOOST_CHECK((SourceLocation{0, 3, source} == SourceLocation{0, 3, source}));
	BOOST_CHECK((SourceLocation{3, 7, source}.contains(SourceLocation{4, 6, source})));
	BOOST_CHECK((!SourceLocation{3, 7, sourceA}.contains(SourceLocation{4, 6, sourceB})));
	BOOST_CHECK((SourceLocation{3, 7, sourceA} < SourceLocation{4, 6, sourceB}));
}

BOOST_AUTO_TEST_SUITE_END()

} // end namespaces
