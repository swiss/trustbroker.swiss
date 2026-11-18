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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcUrl;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.oidc.session.TomcatSession;
import swiss.trustbroker.oidc.session.TomcatSessionManager;
import swiss.trustbroker.util.ApiSupport;

class SessionTxWrapperTest {

	private static final String CLIENT_ID = "test-client";
	private static final String REDIRECT_URI = "https://app.example.com/callback";

	@Mock
	private TomcatSessionManager tomcatSessionManager;

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private ApiSupport apiSupport;

	private TrustBrokerProperties properties;

	private SessionTxWrapper sessionTxWrapper;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		properties = new TrustBrokerProperties();
		var oidcProps = new OidcProperties();
		oidcProps.setIssuer("https://issuer.example.com");
		properties.setOidc(oidcProps);
		sessionTxWrapper = new SessionTxWrapper(tomcatSessionManager, relyingPartyDefinitions, properties, apiSupport);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
	}

	@ParameterizedTest
	@MethodSource
	void oidcPromptNoneRedirectDoneTest(String prompt, boolean hasSession, boolean clientExists,
			boolean redirectUriValid, boolean expectedResult, boolean expectRedirect) throws Exception {

		var request = new MockHttpServletRequest();
		request.addParameter(OidcUtil.OIDC_PROMPT, prompt);
		request.addParameter(OidcUtil.REDIRECT_URI, REDIRECT_URI);
		request.setRequestURI("/api/v1/authorize");
		var response = new MockHttpServletResponse();

		try (MockedStatic<OidcSessionSupport> sessionSupport = mockStatic(OidcSessionSupport.class);
			 MockedStatic<HttpExchangeSupport> exchangeSupport = mockStatic(HttpExchangeSupport.class)) {

			// Setup session and principal
			var session = mock(TomcatSession.class);
			exchangeSupport.when(HttpExchangeSupport::getRunningHttpSession).thenReturn(session);
			sessionSupport.when(() -> OidcSessionSupport.getOidcClientId(any(), any())).thenReturn(CLIENT_ID);

			if (hasSession) {
				var principal = mock(Saml2AuthenticatedPrincipal.class);
				doReturn("user@example.com").when(principal).getName();
				sessionSupport.when(() -> OidcSessionSupport.getAuthenticatedPrincipal(session)).thenReturn(principal);
			} else {
				sessionSupport.when(() -> OidcSessionSupport.getAuthenticatedPrincipal(session)).thenReturn(null);
			}

			// Setup client lookup
			if (clientExists) {
				var aclUrl = redirectUriValid ? REDIRECT_URI : "https://other.example.com";
				var acl = new AcWhitelist(List.of(AcUrl.builder().url(aclUrl).format(AcceptedUrlFormat.FULL).build()));
				var client = OidcClient.builder().id(CLIENT_ID).redirectUris(acl).build();
				doReturn(Optional.of(client)).when(relyingPartyDefinitions).getOidcClientConfigById(eq(CLIENT_ID), any());
			} else {
				doReturn(Optional.empty()).when(relyingPartyDefinitions).getOidcClientConfigById(any(), any());
			}

			doReturn("https://error.example.com").when(apiSupport).getErrorPageUrl(any(), any());

			// Execute
			var result = sessionTxWrapper.oidcPromptNoneRedirectDone(request, response);

			// Verify
			assertEquals(expectedResult, result);
			if (expectRedirect) {
				verify(apiSupport).getErrorPageUrl(any(), any());
				assertEquals(302, response.getStatus());
			} else {
				verify(apiSupport, never()).getErrorPageUrl(any(), any());
			}
		}
	}

	static Stream<Arguments> oidcPromptNoneRedirectDoneTest() {
		return Stream.of(
				// prompt != "none" → false, no redirect
				Arguments.of("login", false, true, true, false, false),
				// prompt = "none", user logged in → false, no redirect (let request continue)
				Arguments.of("none", true, true, true, false, false),
				// prompt = "none", not logged in, client not found → false, no redirect
				Arguments.of("none", false, false, true, false, false),
				// prompt = "none", not logged in, client exists, redirectUri not in ACL → false, no redirect
				Arguments.of("none", false, true, false, false, false),
				// prompt = "none", not logged in, client exists, redirectUri in ACL → true, redirect sent
				Arguments.of("none", false, true, true, true, true)
		);
	}
}

