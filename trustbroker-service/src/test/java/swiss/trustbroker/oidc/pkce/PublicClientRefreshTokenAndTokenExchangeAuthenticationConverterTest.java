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

package swiss.trustbroker.oidc.pkce;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.util.ApiSupport;

class PublicClientRefreshTokenAndTokenExchangeAuthenticationConverterTest {

	@Test
	void isPKCETokenExchangeTest() {
		// Valid PKCE token exchange: POST /token, grant_type=token-exchange, no auth header, no client credentials
		var validRequest = baseTokenExchangeRequest();
		assertTrue(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(validRequest));

		// Returns false: URI doesn't end with /token
		var wrongUri = baseTokenExchangeRequest();
		wrongUri.setRequestURI("/api/v1/wrong");
		assertFalse(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(wrongUri));

		// Returns false: Method is not POST
		var getMethod = baseTokenExchangeRequest();
		getMethod.setMethod("GET");
		assertFalse(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(getMethod));

		// Returns false: grant_type is not token-exchange
		var wrongGrantType = baseTokenExchangeRequest();
		wrongGrantType.removeParameter(OidcUtil.GRANT_TYPE);
		wrongGrantType.addParameter(OidcUtil.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
		assertFalse(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(wrongGrantType));

		// Returns false: Authorization header is present
		var withAuthHeader = baseTokenExchangeRequest();
		withAuthHeader.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");
		assertFalse(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(withAuthHeader));

		// Returns true: Authorization header is blank (blank is treated as "not present")
		var withBlankAuthHeader = baseTokenExchangeRequest();
		withBlankAuthHeader.addHeader(HttpHeaders.AUTHORIZATION, "   ");
		assertTrue(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(withBlankAuthHeader));

		// Returns false: Both client_id and client_secret are in body
		var withClientCredentials = baseTokenExchangeRequest();
		withClientCredentials.addParameter(OidcUtil.OIDC_CLIENT_ID, "my-client");
		withClientCredentials.addParameter(OidcUtil.CLIENT_SECRET, "my-secret");
		assertFalse(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(withClientCredentials));

		// Returns true: Only client_id is present (no client_secret) - this is valid for public clients
		var withClientIdOnly = baseTokenExchangeRequest();
		withClientIdOnly.addParameter(OidcUtil.OIDC_CLIENT_ID, "my-client");
		assertTrue(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(withClientIdOnly));

		// Returns true: Only client_secret is present (no client_id) - edge case but allowed
		var withClientSecretOnly = baseTokenExchangeRequest();
		withClientSecretOnly.addParameter(OidcUtil.CLIENT_SECRET, "my-secret");
		assertTrue(PublicClientRefreshTokenAndTokenExchangeAuthenticationConverter.isPKCETokenExchange(withClientSecretOnly));
	}

	private static MockHttpServletRequest baseTokenExchangeRequest() {
		var request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setScheme("https");
		request.setServerName("server.example.com");
		request.setServerPort(443);
		request.setRequestURI("/api/v1" + ApiSupport.OIDC_TOKEN);
		request.addParameter(OidcUtil.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		return request;
	}
}

