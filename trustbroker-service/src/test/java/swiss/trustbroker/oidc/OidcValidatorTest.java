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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import swiss.trustbroker.federation.xmlconfig.Audiences;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Resources;

@SpringBootTest(classes = OidcValidatorTest.class)
class OidcValidatorTest {

	@Test
	void validateClaimsProviderMappingTest() {
		// No ClaimsProviderMappings in RP config
		var relyingParty1 = givenRelyingParty("any");
		var ex = assertThrows(OAuth2AuthenticationException.class, () ->
				OidcValidator.validateClaimsProviderMapping(relyingParty1, null, "error_uri"));
		assertEquals("unauthorized client", ex.getError().getDescription());

		// CP is not configured for RP
		var cpId1 = "cpId1";
		var relyingParty2 = givenRelyingParty("any", cpId1);
		var cp = ClaimsParty.builder()
							.id("cpId2")
							.build();
		ex = assertThrows(OAuth2AuthenticationException.class, () ->
				OidcValidator.validateClaimsProviderMapping(relyingParty2, cp, "error_uri"));
		assertEquals("unauthorized client", ex.getError().getDescription());

		// CP configured for RP
		assertDoesNotThrow(() -> OidcValidator.validateClaimsProviderMapping(relyingParty2, ClaimsParty.builder().id(cpId1).build(), "error_uri"));
	}

	private RelyingParty givenRelyingParty(String rpId, String... cpIds) {
		ClaimsProviderMappings claimsProviderMappings = null;
		if (cpIds.length > 0) {
			var cps = new ArrayList<ClaimsProvider>();
			for (var cpId : cpIds) {
				cps.add(ClaimsProvider.builder()
									  .id(cpId)
									  .build());
			}

			claimsProviderMappings = ClaimsProviderMappings.builder()
														   .claimsProviderList(cps)
														   .build();
		}

		return RelyingParty.builder()
						   .id(rpId)
						   .claimsProviderMappings(claimsProviderMappings)
						   .build();
	}

	@Test
	void validateInputParamsTest() {
		var oidcClient = OidcClient.builder().build();
		var errorUri = "https://errors.example.com";

		var registeredClient = RegisteredClient.withId("reg-1")
											   .clientId("clientA")
											   .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE.getType())
											   .build();

		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuth =
				mock(OAuth2TokenExchangeAuthenticationToken.class);

		// rpOidcClient empty OR registeredClient null
		OidcClient noClient = null;
		var ex = assertThrows(OAuth2AuthenticationException.class, () -> OidcValidator.validateInputParams(
				noClient, registeredClient, "clientA", tokenExchangeAuth, errorUri));
		assertEquals("invalid request", ex.getError().getDescription());
		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());

		ex = assertThrows(OAuth2AuthenticationException.class, () -> OidcValidator.validateInputParams(
				oidcClient, null, "clientA", tokenExchangeAuth, errorUri));
		assertEquals("invalid request", ex.getError().getDescription());
		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());

		// Missing TOKEN_EXCHANGE grant type
		var missingGrantType = RegisteredClient.withId("reg-2")
											   .clientId("clientA")
											   .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE.getType())
											   .redirectUri("https://redirect.example.com")
											   .build();
		ex = assertThrows(OAuth2AuthenticationException.class, () -> OidcValidator.validateInputParams(
				oidcClient, missingGrantType, "clientA", tokenExchangeAuth, errorUri));
		assertEquals("invalid grant", ex.getError().getDescription());
		assertEquals(OAuth2ErrorCodes.INVALID_GRANT, ex.getError().getErrorCode());

		// requested_token_type = JWT but access token format is NOT SELF_CONTAINED
		var wrongTokenFormat = RegisteredClient.withId("reg-3")
											   .clientId("clientA")
											   .tokenSettings(TokenSettings.builder()
																		   .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
																		   .build())
											   .redirectUri("https://redirect.example.com")
											   .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE.getType())
											   .build();

		when(tokenExchangeAuth.getRequestedTokenType())
				.thenReturn("urn:ietf:params:oauth:token-type:jwt");
		ex = assertThrows(OAuth2AuthenticationException.class, () -> OidcValidator.validateInputParams(
				oidcClient, wrongTokenFormat, "clientA", tokenExchangeAuth, errorUri));
		assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());

		// Valid case: no exception expected
		var valid = RegisteredClient.withId("reg-4")
									.clientId("clientA")
									.tokenSettings(TokenSettings.builder()
																.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
																.build())
									.redirectUri("https://redirect.example.com")
									.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE.getType())
									.build();

		when(tokenExchangeAuth.getRequestedTokenType()).thenReturn("other-type");
		assertDoesNotThrow(() ->
				OidcValidator.validateInputParams(
						oidcClient, valid, "clientA", tokenExchangeAuth, errorUri)
		);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"confAud1,null,true",
			"null,reqAud1,true",
			"confAud1 reqAud1,reqAud1,false",
			"confAud1 reqAud1 reqAud2,reqAud1 reqAud2,false",
			"confAud1 reqAud1 reqAud2,reqAud1 reqAud3,true"},
			nullValues = { "null" })
	void validateRequestedAudiencesTest(String configAudiences, String requestedAudiences, boolean invalid) {
		var errorUri = "https://errors.example.com";

		var oidcClient = OidcClient.builder().build();
		if (configAudiences != null) {
			oidcClient.setAudiences(Audiences.builder().audiencesList(Set.of(configAudiences.split(" "))).build());
		}
		Set<String> reqAud = requestedAudiences != null ? Set.of(requestedAudiences.split(" ")) : null;
		if (invalid) {
			assertThrows(OAuth2AuthenticationException.class, () ->
					OidcValidator.validateRequestedAudiences(reqAud, oidcClient, errorUri));
		}
		else {
			assertDoesNotThrow(() -> OidcValidator.validateRequestedAudiences(reqAud, oidcClient, errorUri));
		}
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"https://conf1.example.com/,null,true",
			"null,https://api1.example.com/,true",
			"https://conf1.example.com/ https://api1.example.com/,https://api1.example.com/,false",
			"https://conf1.example.com/ https://api1.example.com/ https://api2.example.com/,https://api1.example.com/ https://api2.example.com/,false",
			"https://conf1.example.com/ https://api1.example.com/ https://api2.example.com/,https://api1.example.com/ https://api3.example.com/,true"},
			nullValues = { "null" })
	void validateRequestResourcessTest(String configResources, String requestedResources, boolean invalid) {
		var errorUri = "https://errors.example.com";

		var oidcClient = OidcClient.builder().build();
		if (configResources != null) {
			oidcClient.setResources(Resources.builder().resourceList(Set.of(configResources.split(" "))).build());
		}
		Set<String> reqAud = requestedResources != null ? Set.of(requestedResources.split(" ")) : null;
		if (invalid) {
			assertThrows(OAuth2AuthenticationException.class, () ->
					OidcValidator.validateRequestResources(reqAud, oidcClient, errorUri));
		}
		else {
			assertDoesNotThrow(() -> OidcValidator.validateRequestResources(reqAud, oidcClient, errorUri));
		}
	}
}
