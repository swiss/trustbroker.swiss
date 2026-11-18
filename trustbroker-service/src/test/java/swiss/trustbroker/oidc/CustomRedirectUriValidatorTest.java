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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.AcUrl;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.OidcClient;

@SpringBootTest(classes = CustomRedirectUriValidator.class)
class CustomRedirectUriValidatorTest {

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private CustomRedirectUriValidator customRedirectUriValidator;

	@Test
	void testValidateRedirectUri() {
		var redirectUris = List.of(AcUrl.ofFormat("http://test.trustbroker.swiss/.*", AcceptedUrlFormat.REGEX),
				AcUrl.of("http://test.trustbroker.swiss"));
		var registeredClient = RegisteredClient.withId("ANY")
											   .clientId("clientId")
											   .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
											   .redirectUris(uris -> uris.addAll(redirectUris.stream().map(AcceptedUrl::getUrl).toList()))
											   .build();
		mockOidcClient(registeredClient, redirectUris);
		var token = givenToken(registeredClient);

		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "requestedRedirectUri");
		});

		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "http://test3.com");
		});

		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "http://test.trustbroker.swiss:5010");
		});

		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "https://test.trustbroker.swiss");
		});

		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "http://test.trustbroker.swiss/#page");
		});

		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "http://test.trustbroker.swiss/?#page");
		});

		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "http://test.trustbroker.swiss/#?page");
		});

		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "http://test.trustbroker.swiss/page");
		});
	}

	private void mockOidcClient(RegisteredClient registeredClient, List<AcUrl> redirectUrls) {
		var whitelist = AcWhitelist.builder()
								   .acUrls(redirectUrls)
								   .build();
		var client = OidcClient.builder()
							   .id(registeredClient.getClientId())
							   .redirectUris(whitelist)
							   .build();
		when(relyingPartyDefinitions.getOidcClientConfigById(registeredClient.getClientId(), trustBrokerProperties))
				.thenReturn(Optional.of(client));
	}

	@Test
	void testValidateRedirectUriLoopBackAddress() {
		var redirectUris = List.of(AcUrl.ofFormat("http://test.trustbroker.swiss/.*", AcceptedUrlFormat.REGEX),
				AcUrl.ofFormat("http://localhost:0/*", AcceptedUrlFormat.ANY),
				AcUrl.ofFormat("https://localhost:0/*", AcceptedUrlFormat.ANY));
		var registeredClient = RegisteredClient
				.withId("ANY")
				.clientId("clientId")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUris(uris -> uris.addAll(redirectUris.stream().map(AcceptedUrl::getUrl).toList()))
				.build();
		mockOidcClient(registeredClient, redirectUris);
		var token = givenToken(registeredClient);

		// localhost representations with default ports
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "http://localhost");
		});
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "https://localhost");
		});
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "https://localhost.localdomain");
		});

		// localhost representations with any ports
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "https://localhost:5220");
		});
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "https://localhost:5220");
		});
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, null, "https://localhost:5220/");
		});
		assertDoesNotThrow(() -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "https://127.0.0.1:5220");
		});

		// failing
		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "https://localhost.fake.com");
		});
	}

	@Test
	void testValidateRedirectUriInvalidHostName() {
		var redirectUris = List.of(AcUrl.of("https://zzz.test.any.trustbroker.swiss"),
				AcUrl.of("https://dev_service-ws.app.trustbroker.swiss/any"));
		var registeredClient = RegisteredClient.withId("ANY")
											   .clientId("clientId")
											   .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
											   .redirectUris(uris -> uris.addAll(redirectUris.stream().map(AcceptedUrl::getUrl).toList()))
											   .build();
		mockOidcClient(registeredClient, redirectUris);
		var token = givenToken(registeredClient);
		assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> {
			customRedirectUriValidator.validateRedirectUri(
					registeredClient, token, "https://dev_service-ws.app.ch/any");
		});
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken givenToken(
			RegisteredClient registeredClient) {
		// minimal valid object
		List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority("role1"));
		var principal = new DefaultOAuth2AuthenticatedPrincipal(Map.of("name", "dummy"),
				grantedAuthorities);
		return new OAuth2AuthorizationCodeRequestAuthenticationToken("https://localhost/authorize",
				registeredClient.getClientId(), new AnonymousAuthenticationToken("key", principal, grantedAuthorities),
				null, null, Collections.emptySet(), Collections.emptyMap());
	}

}
