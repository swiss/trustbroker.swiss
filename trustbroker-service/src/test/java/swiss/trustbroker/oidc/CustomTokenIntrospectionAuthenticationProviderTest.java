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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@SuppressWarnings("unchecked")
class CustomTokenIntrospectionAuthenticationProviderTest {

	@ParameterizedTest(name = "{0}")
	@MethodSource("withActiveTokenClaimsScenarios")
	void withActiveTokenClaimsScenarios(String testName, String clientId, Map<String, Object> claims, OAuth2Token token,
			boolean expectStandardClaims) {
		var authorizedToken = authorizedTokenMock();
		doReturn(claims).when(authorizedToken).getClaims();
		doReturn(token).when(authorizedToken).getToken();

		var introspection = CustomTokenIntrospectionAuthenticationProvider.withActiveTokenClaims(authorizedToken,
				registeredClient(clientId));

		assertTrue(introspection.isActive());
		assertEquals(clientId, introspection.getClaims().get(OAuth2TokenIntrospectionClaimNames.CLIENT_ID));
		if (expectStandardClaims) {
			assertInstanceOf(URL.class, introspection.getClaims().get(OAuth2TokenIntrospectionClaimNames.ISS));
			assertInstanceOf(List.class, introspection.getClaims().get(OAuth2TokenIntrospectionClaimNames.SCOPE));
			assertInstanceOf(List.class, introspection.getClaims().get(OAuth2TokenIntrospectionClaimNames.AUD));
			assertTrue(introspection.getClaims().containsKey(OAuth2TokenIntrospectionClaimNames.IAT));
			assertTrue(introspection.getClaims().containsKey(OAuth2TokenIntrospectionClaimNames.EXP));
		}
		else {
			assertFalse(introspection.getClaims().containsKey(OAuth2TokenIntrospectionClaimNames.ISS));
			assertFalse(introspection.getClaims().containsKey(OAuth2TokenIntrospectionClaimNames.IAT));
			assertFalse(introspection.getClaims().containsKey(OAuth2TokenIntrospectionClaimNames.EXP));
		}
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("convertClaimsScenarios")
	void convertClaimsIfNecessaryScenarios(String testName, Map<String, Object> claims, boolean expectUnchanged)
			throws Exception {

		var converted = invokeConvertClaimsIfNecessary(claims);

		assertTrue(converted.containsKey(OAuth2TokenIntrospectionClaimNames.ISS));
		assertTrue(converted.containsKey(OAuth2TokenIntrospectionClaimNames.SCOPE));
		assertTrue(converted.containsKey(OAuth2TokenIntrospectionClaimNames.AUD));
		if (expectUnchanged) {
			assertEquals(claims, converted);
		}
		else {
			assertNotEquals(claims, converted);
			assertInstanceOf(URL.class, converted.get(OAuth2TokenIntrospectionClaimNames.ISS));
			assertInstanceOf(List.class, converted.get(OAuth2TokenIntrospectionClaimNames.SCOPE));
			assertInstanceOf(List.class, converted.get(OAuth2TokenIntrospectionClaimNames.AUD));
		}
	}

	private static Stream<Arguments> withActiveTokenClaimsScenarios() {
		var issuedAt = Instant.now().minusSeconds(30);
		var expiresAt = Instant.now().plusSeconds(300);
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt,
				Set.of("scope1"));

		Map<String, Object> stringClaims = new HashMap<>();
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, URI.create("https://issuer.example.org"));
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, "scope1");
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, "aud1");

		var tokenWithoutTimes = mock(OAuth2Token.class);
		doReturn(null).when(tokenWithoutTimes).getIssuedAt();
		doReturn(null).when(tokenWithoutTimes).getExpiresAt();

		return Stream.of(
				Arguments.of("claims and timestamps are propagated", "client-a", stringClaims, accessToken, true),
				Arguments.of("empty claims still produces active introspection", "client-b", Map.<String, Object>of(),
						tokenWithoutTimes, false)
		);
	}

	private static Stream<Arguments> convertClaimsScenarios() throws Exception {
		Map<String, Object> stringClaims = new HashMap<>();
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, URI.create("https://issuer.example.org"));
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, "scope1");
		stringClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, "aud1");

		Map<String, Object> convertedClaims = new HashMap<>();
		convertedClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, URI.create("https://issuer.example.org").toURL());
		convertedClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, List.of("scope1", "scope2"));
		convertedClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, List.of("aud1", "aud2"));

		return Stream.of(
				Arguments.of("string claims are converted", stringClaims, false),
				Arguments.of("already converted claims stay unchanged", convertedClaims, true)
		);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> invokeConvertClaimsIfNecessary(Map<String, Object> claims) throws Exception {
		Method method = CustomTokenIntrospectionAuthenticationProvider.class
				.getDeclaredMethod("convertClaimsIfNecessary", Map.class);
		method.setAccessible(true);
		return (Map<String, Object>) method.invoke(null, claims);
	}

	private static RegisteredClient registeredClient(String clientId) {
		return RegisteredClient.withId("reg-" + clientId)
				.clientId(clientId)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
	}

	@SuppressWarnings("unchecked")
	private static OAuth2Authorization.Token<OAuth2Token> authorizedTokenMock() {
		return (OAuth2Authorization.Token<OAuth2Token>) mock(OAuth2Authorization.Token.class);
	}
}

