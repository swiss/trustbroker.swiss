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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

class CustomRefreshTokenGeneratorTest {

	@ParameterizedTest(name = "{0}")
	@MethodSource("expirationScenarios")
	@SuppressWarnings("unchecked")
	void computeRefreshTokenExpirationScenarios(String testName, Duration ttl, Long currentExpirationOffsetSec,
			Long expectedExpirationOffsetSec) {
		var generator = newGenerator();
		var issuedAt = Instant.now();
		var client = registeredClient("client-a", ttl);

		var context = mock(OAuth2TokenContext.class);
		doReturn(client).when(context).getRegisteredClient();

		var authorization = mock(OAuth2Authorization.class);
		doReturn(authorization).when(context).getAuthorization();

		if (currentExpirationOffsetSec == null) {
			doReturn(null).when(authorization).getRefreshToken();
		}
		else {
			OAuth2Authorization.Token<OAuth2RefreshToken> currentRefreshToken =
					(OAuth2Authorization.Token<OAuth2RefreshToken>) mock(OAuth2Authorization.Token.class);
			var currentExpiration = issuedAt.plusSeconds(currentExpirationOffsetSec);
			doReturn(new OAuth2RefreshToken("refresh", issuedAt.minusSeconds(60), currentExpiration))
					.when(currentRefreshToken).getToken();
			doReturn(currentRefreshToken).when(authorization).getRefreshToken();
		}

		var expiresAt = generator.computeRefreshTokenExpiration(context, issuedAt);

		assertEquals(issuedAt.plusSeconds(expectedExpirationOffsetSec), expiresAt, testName);
	}

	private static Stream<Arguments> expirationScenarios() {
		return Stream.of(
				Arguments.of("keeps current expiration when still valid", Duration.ofMinutes(30), 900L, 900L),
				Arguments.of("uses token settings when no current refresh token exists", Duration.ofMinutes(15), null, 900L),
				Arguments.of("recomputes from token settings when current expiration is not after issuedAt",
						Duration.ofMinutes(20), 0L, 1200L)
		);
	}

	@Test
	void buildClaimsIncludesMandatoryAndOptionalClaims() {
		var issuedAt = Instant.now();
		var expiresAt = issuedAt.plusSeconds(300);
		var context = mock(OAuth2TokenContext.class);
		doReturn(registeredClient("client-1", Duration.ofMinutes(5))).when(context).getRegisteredClient();

		var principal = mock(Authentication.class);
		doReturn("subject-1").when(principal).getName();
		doReturn(principal).when(context).getPrincipal();
		doReturn(Set.of("scope1", "scope2")).when(context).getAuthorizedScopes();

		var authorizationServerContext = mock(AuthorizationServerContext.class);
		doReturn("https://issuer.example.org").when(authorizationServerContext).getIssuer();
		doReturn(authorizationServerContext).when(context).getAuthorizationServerContext();

		JwtClaimsSet claims = CustomRefreshTokenGenerator.buildClaims(context, issuedAt, expiresAt, "sid-1", "nonce-1");

		assertEquals("https://issuer.example.org", claims.getClaims().get("iss").toString());
		assertEquals("subject-1", claims.getClaims().get("sub"));
		assertEquals("Refresh", claims.getClaims().get(OidcUtil.OIDC_TOKEN_TYPE));
		assertEquals(Collections.singletonList("client-1"), claims.getClaims().get("aud"));
		assertEquals("client-1", claims.getClaims().get(OidcUtil.OIDC_AUTHORIZED_PARTY));
		assertEquals(Set.of("scope1", "scope2"), claims.getClaims().get(OidcUtil.OIDC_SCOPE));
		assertEquals("nonce-1", claims.getClaims().get(OidcParameterNames.NONCE));
		assertEquals("sid-1", claims.getClaims().get(OidcUtil.OIDC_SESSION_ID));
		assertEquals("sid-1", claims.getClaims().get(OidcUtil.OIDC_SESSION_STATE));
		assertEquals(issuedAt, asInstant(claims.getClaims().get("iat")));
		assertEquals(expiresAt, asInstant(claims.getClaims().get("exp")));
		assertEquals(issuedAt, asInstant(claims.getClaims().get("nbf")));
		assertTrue(claims.getClaims().containsKey("jti"));
	}

	@Test
	void buildClaimsOmitsOptionalClaimsWhenValuesAreMissing() {
		var issuedAt = Instant.now();
		var expiresAt = issuedAt.plusSeconds(300);
		var context = mock(OAuth2TokenContext.class);
		doReturn(registeredClient("client-2", Duration.ofMinutes(5))).when(context).getRegisteredClient();

		var principal = mock(Authentication.class);
		doReturn("subject-2").when(principal).getName();
		doReturn(principal).when(context).getPrincipal();
		doReturn(Collections.<String>emptySet()).when(context).getAuthorizedScopes();
		doReturn(null).when(context).getAuthorizationServerContext();

		JwtClaimsSet claims = CustomRefreshTokenGenerator.buildClaims(context, issuedAt, expiresAt, null, null);

		assertFalse(claims.getClaims().containsKey("iss"));
		assertFalse(claims.getClaims().containsKey(OidcUtil.OIDC_SCOPE));
		assertFalse(claims.getClaims().containsKey(OidcParameterNames.NONCE));
		assertFalse(claims.getClaims().containsKey(OidcUtil.OIDC_SESSION_ID));
		assertFalse(claims.getClaims().containsKey(OidcUtil.OIDC_SESSION_STATE));
	}

	private static CustomRefreshTokenGenerator newGenerator() {
		return new CustomRefreshTokenGenerator(
				mock(JwtEncoder.class),
				null,
				mock(OAuth2RefreshTokenGenerator.class),
				mock(TrustBrokerProperties.class),
				mock(RelyingPartyDefinitions.class)
		);
	}

	private static RegisteredClient registeredClient(String clientId, Duration refreshTokenTtl) {
		var tokenSettings = mock(TokenSettings.class);
		doReturn(refreshTokenTtl).when(tokenSettings).getRefreshTokenTimeToLive();
		var client = mock(RegisteredClient.class);
		doReturn(clientId).when(client).getClientId();
		doReturn(tokenSettings).when(client).getTokenSettings();
		return client;
	}

	private static Instant asInstant(Object claimValue) {
		if (claimValue instanceof Instant instant) {
			return instant;
		}
		if (claimValue instanceof Number number) {
			return Instant.ofEpochSecond(number.longValue());
		}
		throw new IllegalArgumentException("Unsupported timestamp claim type=" +
				(claimValue != null ? claimValue.getClass().getName() : "null"));
	}
}

