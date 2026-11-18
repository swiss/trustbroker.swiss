/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.profileselection.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Tests for common profile selection logic in the abstract IdentitySelectionService base class.
 *
 * This class tests the shared logic extracted from LDAP and REST implementations,
 * including profile attribute matching and filtering behavior.
 */
class IdentitySelectionServiceTest {

	/**
	 * Test isProfileAttribute() - a core static utility method from the base class
	 * This is tested via inheritance in the subclass tests (LdapIdentitySelectionServiceTest).
	 */
	@ParameterizedTest
	@CsvSource({
			// Simple exact match
			"profileId,profileId,true",
			// No match - different names
			"profileId,userId,false",
			// No match - no separator in attribute
			"profileId,userName:uniteName,false",
			// Match - attribute has prefix with separator
			"profileId:user,profileId,true",
			// No match - different profile part
			"profileId:user,unitName,false",
			// Match - hierarchical attribute with 3 parts
			"profileId:org:memberOf,profileId,true",
			// No match - attribute has more complex hierarchy
			"profileId:org:memberOf,unitName,false",
			// Match - hierarchical profile selector
			"profileId:org:memberOf,profileId:org,true",
			// No match - different organization
			"profileId:org:memberOf,profileId:org2,false",
			// No match - wrong organization level
			"profileId:org2:memberOf,profileId:org,false",
			// No match - no prefix match
			"profileId:org:memberOf,unit,false"
	})
	void testIsProfileAttribute(String profileAttr, String profilePrefix, boolean expected) {
		// Note: isProfileAttribute is tested through the LdapIdentitySelectionService test
		// because it's inherited from the base class. This is a template for understanding
		// the behavior of the core profile attribute matching logic.
		boolean result = IdentitySelectionService.isProfileAttribute(profileAttr, profilePrefix);
		assertEquals(expected, result);
	}

	/**
	 * Test that profile separators are correctly handled
	 */
	@ParameterizedTest
	@CsvSource({
			"profileId",
			"profileId:subId",
			"profileId:org:memberOf",
			"simpleId"
	})
	void testProfileSeparatorHandling(String profileId) {
		// All profiles should match themselves exactly
		assertTrue(IdentitySelectionService.isProfileAttribute(profileId, profileId));
	}

	/**
	 * Test edge cases for profile attribute matching
	 */
	@Test
	void testProfileAttributeEdgeCases() {
		// Empty strings
		assertFalse(IdentitySelectionService.isProfileAttribute("", ""));

		// Null-like behavior (actual null would throw NPE, which is expected)
		assertFalse(IdentitySelectionService.isProfileAttribute("test", ""));
		assertFalse(IdentitySelectionService.isProfileAttribute("", "test"));

		// Partial matches should not work
		assertFalse(IdentitySelectionService.isProfileAttribute("profile", "pro"));

		// Case sensitive
		assertFalse(IdentitySelectionService.isProfileAttribute("ProfileId", "profileId"));
	}

	/**
	 * Test profile attribute with same prefix but longer attribute
	 */
	@ParameterizedTest
	@CsvSource({
			"admin,admin,true",
			"admin:permissions,admin,true",
			"admin:org:roles,admin,true",
			"user:admin,admin,false",
			"administrator,admin,false"
	})
	void testProfilePrefixMatching(String profileAttr, String profilePrefix, boolean expected) {
		assertEquals(expected, IdentitySelectionService.isProfileAttribute(profileAttr, profilePrefix));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"groupList,groupList",
			"IDM:groupList,groupList",
			"IDM:rest1:groupList,groupList",
			"CP:issuer:uid,uid",
			":,:",
			"'',''",
			"null,null"
	}, nullValues = "null")
	void computeProfileSelectorTest(String profileSelector, String expectedSelector) throws Exception {
		assertEquals(expectedSelector, invokeComputeProfileSelector(profileSelector));
	}

	@Test
	void computeProfileSelectorBlankValueIsReturnedAsIs() throws Exception {
		assertEquals("   ", invokeComputeProfileSelector("   "));
	}

	private static String invokeComputeProfileSelector(String profileSelector) throws Exception {
		Method method = IdentitySelectionService.class.getDeclaredMethod("computeProfileSelector", String.class);
		method.setAccessible(true);
		return (String) method.invoke(null, profileSelector);
	}
}

