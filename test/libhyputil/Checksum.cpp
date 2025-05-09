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
 * Unit tests for the address checksum.
 */

#include <libhyputil/CommonData.h>
#include <libhyputil/Exceptions.h>

#include <test/Common.h>

#include <boost/test/unit_test.hpp>


namespace hyperion::util::test
{

BOOST_AUTO_TEST_SUITE(Checksum)

BOOST_AUTO_TEST_CASE(calculate)
{
	BOOST_CHECK(!getChecksummedAddress("Zdf81da12dbbb1300cd8725887bd50ecff9e6f57297c4c5a3").empty());
	BOOST_CHECK(!getChecksummedAddress("Z0123456789abcdefABCDEF0123456789abcdefABCDEF0123").empty());
	// no prefix
	BOOST_CHECK_THROW(getChecksummedAddress("df81da12dbbb1300cd8725887bd50ecff9e6f57297c4c5a3"), InvalidAddress);
	// too short
	BOOST_CHECK_THROW(getChecksummedAddress("Zdf81da12dbbb1300cd8725887bd50ecff9e6f57297c4c5a3"), InvalidAddress);
	// too long
	BOOST_CHECK_THROW(getChecksummedAddress("Zdf81da12dbbb1300cd8725887bd50ecff9e6f57297c4c5a31"), InvalidAddress);
	// non-hex character
	BOOST_CHECK_THROW(getChecksummedAddress("Zdf81da12dbbb1300cd8725887bd50ecff9e6f57297c4c5aK"), InvalidAddress);

	// the official test suite from EIP-55
	std::vector<std::string> cases {
		// all upper case
		"ZA377CBC7E2EED6C1C26F652B83CB0456C91B8499A936EDD5",
		"ZE7A35105750CD36E9A3C3035E4E46A7A9E9539FEC6D51F8C",
		// all lower case
		"Ze0e3afa8e503fbd835229cf329580e418c682add7478db62",
		"Z0db9576bb8227afd79a6059b6bc6a012ffD2ec594d394910",
		// regular
		"ZdF81dA12DBBB1300Cd8725887BD50eCFf9E6F57297C4c5a3",
		"Z7F27fbe155e575f6387a95F2cCec19A67F28b3e9a6aeCaB0",
		"Z2eBA8b7e1D3Ada69CB71D79A25f9Ae891a13D38cB668F431",
		"ZAF5036a2CBea16D47a825F701b062f721c4fC9A3139Da472"
	};

	for (size_t i = 0; i < cases.size(); i++)
		BOOST_REQUIRE_MESSAGE(getChecksummedAddress(cases[i]) == cases[i], cases[i]);
}

BOOST_AUTO_TEST_CASE(regular)
{
	BOOST_CHECK(passesAddressChecksum("ZdF81dA12DBBB1300Cd8725887BD50eCFf9E6F57297C4c5a3", true));
	BOOST_CHECK(passesAddressChecksum("Z7F27fbe155e575f6387a95F2cCec19A67F28b3e9a6aeCaB0", true));
	BOOST_CHECK(passesAddressChecksum("Z2eBA8b7e1D3Ada69CB71D79A25f9Ae891a13D38cB668F431", true));
	BOOST_CHECK(passesAddressChecksum("ZAF5036a2CBea16D47a825F701b062f721c4fC9A3139Da472", true));
}

BOOST_AUTO_TEST_CASE(regular_negative)
{
	BOOST_CHECK(!passesAddressChecksum("Z451809aBc97bd4f223aa0A33e1EA5b426D470bBC3fEE57B3", true));
	BOOST_CHECK(!passesAddressChecksum("Zecd50A2711166eB6a9B12CB54D4621CffdCfA576a2027490", true));
	BOOST_CHECK(!passesAddressChecksum("Z44c9A14640A560958ffc43D628a7C77c0b3B479e022c25dc", true));
	BOOST_CHECK(!passesAddressChecksum("ZEad9850DCa929aa16b0107fd675Ac038369d10Bd951e974F", true));
}

BOOST_AUTO_TEST_CASE(regular_invalid_length)
{
	BOOST_CHECK(passesAddressChecksum("Z9adA1b4B23BcDf70BA9ad26054f9c2a6e143dcD77Ab864a4", true));
	BOOST_CHECK(!passesAddressChecksum("Z9adA1b4B23BcDf70BA9ad26054f9c2a6e143dcD77Ab864a", true));
	BOOST_CHECK(passesAddressChecksum("ZC42f9308f5856268700B48aD380bf53A3403AD3302F57207", true));
	BOOST_CHECK(!passesAddressChecksum("Z42f9308f5856268700B48aD380bf53A3403AD3302F57207", true));
	BOOST_CHECK(passesAddressChecksum("Z028D9d02806cE32932FD127e4B4Cd8bF76646A7654BD7dEA", true));
	BOOST_CHECK(!passesAddressChecksum("Z28D9d02806cE32932FD127e4B4Cd8bF76646A7654BD7dEA", true));
	BOOST_CHECK(passesAddressChecksum("Za063338E533c817e06154e5e9F2Fc615a947c44592c5d880", true));
	BOOST_CHECK(!passesAddressChecksum("Za063338E533c817e06154e5e9F2Fc615a947c44592c5d88", true));
}

BOOST_AUTO_TEST_CASE(homocaps_valid)
{
	BOOST_CHECK(passesAddressChecksum("ZA377CBC7E2EED6C1C26F652B83CB0456C91B8499A936EDD5", true));
	BOOST_CHECK(passesAddressChecksum("ZE7A35105750CD36E9A3C3035E4E46A7A9E9539FEC6D51F8C", true));
	BOOST_CHECK(passesAddressChecksum("Ze0e3afa8e503fbd835229cf329580e418c682add7478db62", true));
	BOOST_CHECK(passesAddressChecksum("Z0db9576bb8227afd79a6059b6bc6a012ffD2ec594d394910", true));
}

BOOST_AUTO_TEST_CASE(homocaps_invalid)
{
	std::string upper = "Z00AA0000000012400000000DDEEFF00000000000000000BB";
	BOOST_CHECK(passesAddressChecksum(upper, false));
	BOOST_CHECK(!passesAddressChecksum(upper, true));
	std::string lower = "Z11aa000000000000000d00cc0000000000000000000000bb";
	BOOST_CHECK(passesAddressChecksum(lower, false));
	BOOST_CHECK(!passesAddressChecksum(lower, true));
}

BOOST_AUTO_TEST_SUITE_END()

}
