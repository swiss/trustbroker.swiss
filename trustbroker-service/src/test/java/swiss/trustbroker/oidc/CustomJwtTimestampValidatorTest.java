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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.time.Instant;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;

class CustomJwtTimestampValidatorTest {

	private OidcClient oidcClient;
	private OidcSecurityPolicies securityPolicies;
	private TrustBrokerProperties trustBrokerProperties;
	private SecurityChecks securityChecks;
	private CustomJwtTimestampValidator validator;

	@BeforeEach
	void setUp() {
		oidcClient = mock(OidcClient.class);
		securityPolicies = mock(OidcSecurityPolicies.class);
		trustBrokerProperties = mock(TrustBrokerProperties.class);
		securityChecks = mock(SecurityChecks.class);

		doReturn("client-id").when(oidcClient).getId();
		doReturn(securityPolicies).when(oidcClient).getOidcSecurityPolicies();
		doReturn(securityChecks).when(trustBrokerProperties).getSecurity();

		doReturn(60).when(securityPolicies).getClientAssertionMaxAgeSec();
		doReturn(3600).when(securityPolicies).getClientAssertionExpirationLifeTimeSec();
		doReturn(0).when(securityPolicies).getClientAssertionNotOnOrAfterToleranceSec();
		doReturn(0).when(securityPolicies).getClientAssertionNotBeforeToleranceSec();

		doReturn(0L).when(securityChecks).getNotOnOrAfterToleranceSec();
		doReturn(0L).when(securityChecks).getNotBeforeToleranceSec();

		validator = new CustomJwtTimestampValidator(oidcClient, trustBrokerProperties);
	}

	@Test
	void validateNullTokenThrowsException() {
		assertThrows(IllegalArgumentException.class, () -> validator.validate(null));
	}

	@Test
	void validateWithValidTimestampsReturnsSuccess() {
		var now = Instant.now();
		var jwt = mockJwt(now.minusSeconds(10), now.plusSeconds(30), now.minusSeconds(2));

		var result = validator.validate(jwt);

		assertFalse(result.hasErrors());
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("failureResultCases")
	void validateFailureResultCases(String testName, long iatOffsetSec, long expOffsetSec, long nbfOffsetSec,
			String expectedDescriptionPrefix) {
		var now = Instant.now();
		var jwt = mockJwt(now.plusSeconds(iatOffsetSec), now.plusSeconds(expOffsetSec), now.plusSeconds(nbfOffsetSec));

		var result = validator.validate(jwt);

		assertTrue(result.hasErrors());
		var error = result.getErrors().iterator().next();
		assertEquals("invalid_token", error.getErrorCode());
		assertTrue(error.getDescription().startsWith(expectedDescriptionPrefix));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("exceptionCases")
	void validateExceptionCases(String testName, long iatOffsetSec) {
		var now = Instant.now();
		var jwt = mockJwt(now.plusSeconds(iatOffsetSec), now.plusSeconds(30), now.minusSeconds(2));

		assertThrows(OAuth2AuthenticationException.class, () -> validator.validate(jwt));
	}

	@Test
	void validateFallsBackToGlobalToleranceWhenClientToleranceIsMissing() {
		doReturn(null).when(securityPolicies).getClientAssertionNotOnOrAfterToleranceSec();
		doReturn(null).when(securityPolicies).getClientAssertionNotBeforeToleranceSec();
		doReturn(30L).when(securityChecks).getNotOnOrAfterToleranceSec();
		doReturn(-15L).when(securityChecks).getNotBeforeToleranceSec();

		var now = Instant.now();
		var jwt = mockJwt(now.minusSeconds(10), now.minusSeconds(10), now.plusSeconds(10));

		var result = validator.validate(jwt);

		assertFalse(result.hasErrors());
	}

	private static Stream<Arguments> failureResultCases() {
		return Stream.of(
				Arguments.of("expired token", -10L, -1L, -2L, "Jwt expired at"),
				Arguments.of("expiration lifetime too long", -10L, 7200L, -2L, "Jwt expired at"),
				Arguments.of("not-before in future", -10L, 30L, 20L, "Jwt used before")
		);
	}

	private static Stream<Arguments> exceptionCases() {
		return Stream.of(
				Arguments.of("issued-at in future", 5L),
				Arguments.of("issued-at too old", -120L)
		);
	}

	private Jwt mockJwt(Instant issuedAt, Instant expiresAt, Instant notBefore) {
		var jwt = mock(Jwt.class);
		doReturn(issuedAt).when(jwt).getIssuedAt();
		doReturn(expiresAt).when(jwt).getExpiresAt();
		doReturn(notBefore).when(jwt).getNotBefore();
		return jwt;
	}
}

