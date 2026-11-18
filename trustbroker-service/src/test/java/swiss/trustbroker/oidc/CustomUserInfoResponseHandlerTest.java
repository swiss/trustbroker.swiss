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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import tools.jackson.databind.ObjectMapper;

class CustomUserInfoResponseHandlerTest {

	private static final String CLIENT_ID = "test-client";

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private TrustBrokerProperties trustBrokerProperties;

	@Mock
	private ObjectMapper objectMapper;

	@Mock
	private JWKSource<SecurityContext> jwkSource;

	@Mock
	private OidcEncryptionKeystoreService encryptionKeystoreService;

	private CustomUserInfoResponseHandler handler;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		handler = new CustomUserInfoResponseHandler(relyingPartyDefinitions, trustBrokerProperties,
				objectMapper, jwkSource, encryptionKeystoreService);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
	}

	@ParameterizedTest
	@MethodSource
	void extractClientIdFromClaimsTest(String principalType, Object audience, String expectedClientId) {
		var userInfoToken = mock(OidcUserInfoAuthenticationToken.class);

		if ("jwt".equals(principalType)) {
			var jwt = mock(JwtAuthenticationToken.class);
			doReturn(jwt).when(userInfoToken).getPrincipal();
			doReturn(Map.of(OidcUtil.OIDC_AUDIENCE, audience)).when(jwt).getTokenAttributes();
		} else if ("bearer".equals(principalType)) {
			var bearer = mock(BearerTokenAuthentication.class);
			doReturn(bearer).when(userInfoToken).getPrincipal();
			doReturn(Map.of(OidcUtil.OIDC_AUDIENCE, audience)).when(bearer).getTokenAttributes();
		} else {
			doReturn(new Object()).when(userInfoToken).getPrincipal();
		}

		var result = handler.extractClientIdFromClaims(userInfoToken);

		assertEquals(expectedClientId, result);
	}

	static Stream<Arguments> extractClientIdFromClaimsTest() {
		return Stream.of(
				// JwtAuthenticationToken with single audience string → returns the string
				Arguments.of("jwt", CLIENT_ID, CLIENT_ID),
				// JwtAuthenticationToken with audience collection (1 element) → returns the element
				Arguments.of("jwt", List.of(CLIENT_ID), CLIENT_ID),
				// JwtAuthenticationToken with audience collection (multiple elements) → returns null
				Arguments.of("jwt", List.of("client1", "client2"), null),
				// BearerTokenAuthentication with single audience string → returns the string
				Arguments.of("bearer", CLIENT_ID, CLIENT_ID),
				// BearerTokenAuthentication with audience collection (1 element) → returns the element
				Arguments.of("bearer", List.of(CLIENT_ID), CLIENT_ID),
				// Unknown principal type → returns null
				Arguments.of("other", CLIENT_ID, null)
		);
	}

	@ParameterizedTest
	@MethodSource
	void encryptUserInfoResponseTest(boolean jwkCreationSucceeds, String expectedContentType) {
		var response = new MockHttpServletResponse();
		var claims = Map.<String, Object>of("sub", "user123", "name", "Test User");
		var encryptionParams = OidcEncryptionKeystoreService.EncryptionParams.builder()
				.encryptionAlgorithm("RSA-OAEP-256")
				.encryptionMethod("A256GCM")
				.keyId("key-1")
				.build();

		try (MockedStatic<OidcUtil> oidcUtilMock = mockStatic(OidcUtil.class);
			 MockedStatic<JwkUtil> jwkUtilMock = mockStatic(JwkUtil.class);
			 MockedStatic<JwtUtil> jwtUtilMock = mockStatic(JwtUtil.class)) {

			var jweHeader = mock(JWEHeader.class);
			oidcUtilMock.when(() -> OidcUtil.getJWEHeader(anyBoolean(), anyString(), anyString(), anyString()))
					.thenReturn(jweHeader);

			if (jwkCreationSucceeds) {
				var jwk = mock(JWK.class);
				jwkUtilMock.when(() -> JwkUtil.createEncrptionJWK(any(), anyString(), any())).thenReturn(jwk);
				jwkUtilMock.when(() -> JwkUtil.buildJwsHeader(any())).thenReturn(null);

				var payload = new Payload("signed-payload");
				oidcUtilMock.when(() -> OidcUtil.getAndSignPayload(any(), anyBoolean(), any(), any(), anyString()))
						.thenReturn(payload);

				jwtUtilMock.when(() -> JwtUtil.encryptJwt(any(), any(), any())).thenReturn("encrypted-jwt-token");
			} else {
				jwkUtilMock.when(() -> JwkUtil.createEncrptionJWK(any(), anyString(), any())).thenReturn(null);
			}

			handler.encryptUserInfoResponse(response, claims, encryptionParams, CLIENT_ID);

			assertTrue(response.getContentType() != null && response.getContentType().contains(expectedContentType));
		}
	}

	static Stream<Arguments> encryptUserInfoResponseTest() {
		return Stream.of(
				// JWK creation succeeds → encrypted JWT response
				Arguments.of(true, JwtUtil.APPLICATION_JWT_TYPE),
				// JWK creation fails → falls back to JSON response
				Arguments.of(false, "application/json")
		);
	}
}



