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

package swiss.trustbroker.oidc.tx;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class OidcRequestUtilTest {

	@ParameterizedTest
	@MethodSource
	void cleanScopeParamSpacesMapTest(Map<String, String[]> input, Map<String, String[]> expected) {
		var result = OidcRequestUtil.cleanScopeParamSpaces(input);
		assertEquals(expected.size(), result.size());
		expected.forEach((key, value) -> assertArrayEquals(value, result.get(key)));
	}

	static Stream<Arguments> cleanScopeParamSpacesMapTest() {
		return Stream.of(
				// Trim + collapse spaces in scope, other params unchanged
				Arguments.of(
						Map.of("scope", new String[] { "  openid   profile  email  " }, "client_id", new String[] { "my-client" }),
						Map.of("scope", new String[] { "openid profile email" }, "client_id", new String[] { "my-client" })
				),
				// Multiple scope values in array
				Arguments.of(
						Map.of("scope", new String[] { "  openid  ", "  profile   email  " }),
						Map.of("scope", new String[] { "openid", "profile email" })
				),
				// Map without scope parameter - returns copy unchanged
				Arguments.of(
						Map.of("client_id", new String[] { "my-client" }),
						Map.of("client_id", new String[] { "my-client" })
				)
		);
	}

	@ParameterizedTest
	@MethodSource
	void cleanScopeParamSpacesArrayTest(String[] input, String paramName, String[] expected) {
		var result = OidcRequestUtil.cleanScopeParamSpaces(input, paramName);
		assertArrayEquals(expected, result);
	}

	static Stream<Arguments> cleanScopeParamSpacesArrayTest() {
		return Stream.of(
				// Name is "scope" → trims and collapses spaces
				Arguments.of(new String[] { "  openid   profile  " }, "scope", new String[] { "openid profile" }),
				// Name is not "scope" → returns unchanged
				Arguments.of(new String[] { "  value  with  spaces  " }, "client_id", new String[] { "  value  with  spaces  " }),
				// Multiple values in scope array
				Arguments.of(new String[] { " a  b ", "  c   d  e  " }, "scope", new String[] { "a b", "c d e" }),
				// Already clean scope
				Arguments.of(new String[] { "openid profile" }, "scope", new String[] { "openid profile" })
		);
	}
}
