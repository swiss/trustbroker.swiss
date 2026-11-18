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

package swiss.trustbroker.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

class CustomJwtAudValidatorTest {

	private static final String ISSUER = "https://issuer.example.com";

	private final CustomJwtAudValidator validator = new CustomJwtAudValidator();

	@Test
	void validateNullTokenThrowsException() {
		assertThrows(IllegalArgumentException.class, () -> validator.validate(null));
	}

	@ParameterizedTest
	@MethodSource
	void validateTest(List<String> tokenAudiences, String contextIssuer, boolean expectedSuccess) {
		var jwt = mock(Jwt.class);
		doReturn(tokenAudiences).when(jwt).getAudience();
		doReturn("test-subject").when(jwt).getSubject();

		try (MockedStatic<AuthorizationServerContextHolder> contextHolder = mockStatic(AuthorizationServerContextHolder.class)) {
			var context = mock(AuthorizationServerContext.class);
			doReturn(contextIssuer).when(context).getIssuer();
			contextHolder.when(AuthorizationServerContextHolder::getContext).thenReturn(context);

			var result = validator.validate(jwt);

			assertEquals(expectedSuccess, !result.hasErrors());
			if (!expectedSuccess) {
				assertTrue(result.getErrors().stream()
						.anyMatch(e -> e.getErrorCode().equals("invalid_token")));
			}
		}
	}

	static Stream<Arguments> validateTest() {
		return Stream.of(
				// Token audience matches issuer → success
				Arguments.of(List.of(ISSUER), ISSUER, true),
				// Token has multiple audiences, one matches → success
				Arguments.of(List.of("other-aud", ISSUER), ISSUER, true),
				// Token audience doesn't match issuer → failure
				Arguments.of(List.of("wrong-audience"), ISSUER, false),
				// Token has null audience → failure
				Arguments.of(null, ISSUER, false),
				// Token has empty audience → failure
				Arguments.of(Collections.emptyList(), ISSUER, false),
				// Context has no issuer (empty string) → failure
				Arguments.of(List.of(ISSUER), "", false),
				// Context has null issuer → failure
				Arguments.of(List.of(ISSUER), null, false)
		);
	}
}

