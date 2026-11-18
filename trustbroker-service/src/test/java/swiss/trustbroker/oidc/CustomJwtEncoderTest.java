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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;

class CustomJwtEncoderTest {

	private static final String CLIENT_ID = "test-client";
	private static final String ISSUER = "https://issuer.example.com";

	@Mock
	private TrustBrokerProperties properties;

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private JWKSource<SecurityContext> jwkSource;

	@Mock
	private OidcEncryptionKeystoreService encryptionKeystoreService;

	private CustomJwtEncoder encoder;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		encoder = new CustomJwtEncoder(properties, relyingPartyDefinitions, jwkSource, encryptionKeystoreService);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
	}

	@ParameterizedTest
	@MethodSource
	void encodeTest(String scenario, boolean clientExists, boolean encryptionEnabled, boolean isIdToken,
			boolean hasEncryptionParams, boolean expectException, boolean expectEncryption) {

		var claims = JwtClaimsSet.builder()
				.issuer(ISSUER)
				.subject("user123")
				.claim(OidcUtil.OIDC_AUTHORIZED_PARTY, CLIENT_ID)
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(3600));

		if (isIdToken) {
			claims.claim(OidcUtil.OIDC_TOKEN_TYPE, "ID");
		}

		var jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		var parameters = JwtEncoderParameters.from(jwsHeader, claims.build());

		if (!clientExists) {
			doReturn(Optional.empty()).when(relyingPartyDefinitions).getOidcClientConfigById(anyString(), any());

			assertThrows(TechnicalException.class, () -> encoder.encode(parameters));
			return;
		}

		// Setup client config
		var securityPolicies = OidcSecurityPolicies.builder()
				.requireIdTokenEncryption(encryptionEnabled)
				.encryptionAlgorithm("RSA-OAEP-256")
				.encryptionMethod("A256GCM")
				.build();
		var client = OidcClient.builder()
				.id(CLIENT_ID)
				.oidcSecurityPolicies(securityPolicies)
				.build();
		var relyingParty = RelyingParty.builder().id("rp-1").build();

		doReturn(Optional.of(client)).when(relyingPartyDefinitions).getOidcClientConfigById(anyString(), any());
		doReturn(relyingParty).when(relyingPartyDefinitions).getRelyingPartyByOidcClientId(anyString(), any(), any(), anyBoolean());

		if (hasEncryptionParams) {
			var encParams = OidcEncryptionKeystoreService.EncryptionParams.builder()
					.encryptionAlgorithm("RSA-OAEP-256")
					.encryptionMethod("A256GCM")
					.keyId("key-1")
					.build();
			doReturn(encParams).when(encryptionKeystoreService).getEncryptionParams(any(), any());
		} else {
			doReturn(null).when(encryptionKeystoreService).getEncryptionParams(any(), any());
		}

		if (expectEncryption) {
			try (MockedStatic<OidcUtil> oidcUtilMock = mockStatic(OidcUtil.class);
				 MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {

				oidcUtilMock.when(() -> OidcUtil.isIdToken(any())).thenReturn(isIdToken);
				oidcUtilMock.when(() -> OidcUtil.getJWEHeader(anyBoolean(), anyString(), anyString(), anyString()))
						.thenReturn(mock(JWEHeader.class));

				var mockJwt = Jwt.withTokenValue("encrypted-token")
						.header("alg", "RSA-OAEP-256")
						.claim("sub", "user123")
						.issuedAt(Instant.now())
						.expiresAt(Instant.now().plusSeconds(3600))
						.build();
				jwtUtilMock.when(() -> JwtUtil.generateEncryptedToken(any(), anyBoolean(), any(), any(), any(), anyString()))
						.thenReturn(mockJwt);

				var result = encoder.encode(parameters);

				assertNotNull(result);
				assertEquals("encrypted-token", result.getTokenValue());
			}
		} else {
			try {
				var rsaJwk = new RSAKeyGenerator(2048)
						.keyID("kid-1")
						.generate();
				doReturn(List.<JWK>of(rsaJwk)).when(jwkSource).get(any(JWKSelector.class), ArgumentMatchers.isNull());
			}
			catch (JOSEException e) {
				throw new RuntimeException(e);
			}
			var result = Assertions.assertDoesNotThrow(() -> encoder.encode(parameters));
			assertNotNull(result);
		}
	}

	static Stream<Arguments> encodeTest() {
		return Stream.of(
				// Client not found → throws TechnicalException
				Arguments.of("client not found", false, false, false, false, true, false),
				// Encryption enabled, is ID token, has params → encrypted
				Arguments.of("encryption enabled with params", true, true, true, true, false, true),
				// Encryption enabled, is ID token, no params → falls back to non-encrypted
				Arguments.of("encryption enabled no params", true, true, true, false, false, false),
				// Encryption enabled, not ID token → non-encrypted
				Arguments.of("encryption enabled not id token", true, true, false, true, false, false),
				// Encryption disabled → non-encrypted
				Arguments.of("encryption disabled", true, false, true, false, false, false)
		);
	}
}

