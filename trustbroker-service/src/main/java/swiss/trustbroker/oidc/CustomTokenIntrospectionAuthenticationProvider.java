/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

/**
 * Used to check tokens for validity and content on the OIDC provider
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider
 * NOTE We copied this class including their to-do remarks because this one does OIDC and in the XTB set-up the default one does
 * SAML2 introspection. A bit risky code duplication but not a central functionality in XTB.
 *
 * Javadoc of original class:
 *
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @since 0.1.1
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 Introspection Request</a>
 */
@AllArgsConstructor
@Slf4j
public class CustomTokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

	private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

	private static final TypeDescriptor LIST_STRING_TYPE_DESCRIPTOR =
			TypeDescriptor.collection(List.class, TypeDescriptor.valueOf(String.class));

	private final ClientConfigInMemoryRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// unauthorized
		if (authentication == null) {
			log.warn("OIDC clientId={} did not provide client authorization for token introspection",
					OidcSessionSupport.getOidcClientId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
				(OAuth2TokenIntrospectionAuthenticationToken) authentication;

		Authentication clientPrincipal =
				CustomOAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(tokenIntrospectionAuthentication);

		// no authorization of client, inspect own token then
		OAuth2Authorization authorization = authorizationService.findByToken(
				tokenIntrospectionAuthentication.getToken(), null);
		if (authorization == null) {
			log.debug("OAuth2Authorization authorization for token returned by OAuth2AuthorizationService");
			// Return the authentication request when token not found
			return tokenIntrospectionAuthentication;
		}

		if (log.isTraceEnabled()) {
			log.trace("Retrieved authorization with token");
		}

		// active=false
		OAuth2Authorization.Token<OAuth2Token> authorizedToken =
				authorization.getToken(tokenIntrospectionAuthentication.getToken());
		if (authorizedToken == null) {
			log.warn("OIDC clientId={} did not send a token to introspect",	OidcSessionSupport.getOidcClientId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		var authorizationClient = getAuthorizedClient(authorization.getRegisteredClientId(), authorizedToken);
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(authorizationClient, null, trustBrokerProperties, false);
		var rpClients = relyingParty.getOidcClients().stream().map(OidcClient::getId).collect(Collectors.toSet());
		var clientPrincipalName = getAuthenticationClientId(clientPrincipal);
		if (authorizationClient == null || !rpClients.contains(clientPrincipalName)) {
			log.error("Authentication Client={} is not matching the Authorization client={}", clientPrincipalName, authorizationClient);
			return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
					clientPrincipal, OAuth2TokenIntrospection.builder().build());
		}

		if (!authorizedToken.isActive()) {
			log.info("OAuth2Authorization is active={} invalidated={}  beforeUse={} expired={} expiresAt={} tokenClaims='{}'",
					authorizedToken.isActive(), authorizedToken.isInvalidated(),
					authorizedToken.isBeforeUse(), authorizedToken.isExpired(),
					authorizedToken.getToken().getExpiresAt(), authorizedToken.getClaims());
			return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
					clientPrincipal, OAuth2TokenIntrospection.builder().build());
		}

		// active=true
		RegisteredClient authorizedClient = this.registeredClientRepository.findByClientId(authorizationClient);
		if (authorizedClient == null) {
			log.warn("Registered clientId={} missing", authorizationClient);
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}
		OAuth2TokenIntrospection tokenClaims = withActiveTokenClaims(authorizedToken, authorizedClient);

		if (log.isDebugEnabled()) {
			log.debug("Returning OAuth2TokenIntrospectionAuthenticationToken for clientPrincipal=\"{}\", tokenClaims={}",
					clientPrincipalName, tokenClaims.getClaims());
		}

		return new OAuth2TokenIntrospectionAuthenticationToken(authorizedToken.getToken().getTokenValue(),
				clientPrincipal, tokenClaims);
	}

	private String getAuthorizedClient(String registeredClientId, OAuth2Authorization.Token<OAuth2Token> authorizedToken) {
		var tokenFormat = authorizedToken.getMetadata(OAuth2TokenFormat.class.getName());
		boolean isOpaque = OAuth2TokenFormat.REFERENCE.getValue().equals(tokenFormat);
		if (registeredClientId == null || isOpaque) {
			return registeredClientId;
		}

		var clientIdFromToken = OidcUtil.getClientIdFromTokenClaims(authorizedToken.getClaims());
		return clientIdFromToken == null ? registeredClientId : clientIdFromToken;
	}

	private String getAuthenticationClientId(Authentication clientPrincipal) {
		if (clientPrincipal instanceof Saml2Authentication saml2Authentication &&
				saml2Authentication.getPrincipal() instanceof DefaultSaml2AuthenticatedPrincipal defaultSaml2AuthenticatedPrincipal) {
			return defaultSaml2AuthenticatedPrincipal.getRelyingPartyRegistrationId();
		}
		if (clientPrincipal instanceof OAuth2ClientAuthenticationToken clientAuthenticationToken) {
			var registeredClient = clientAuthenticationToken.getRegisteredClient();
			return registeredClient != null ? registeredClient.getClientId() : null;
		}
		log.error("Could not extract Authentication client id from Principal={}", clientPrincipal);
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	static OAuth2TokenIntrospection withActiveTokenClaims(
			OAuth2Authorization.Token<OAuth2Token> authorizedToken, RegisteredClient authorizedClient) {

		OAuth2TokenIntrospection.Builder tokenClaims;
		Map<String, Object> claims = authorizedToken.getClaims();
		if (!CollectionUtils.isEmpty(claims)) {
			claims = convertClaimsIfNecessary(claims);
			tokenClaims = OAuth2TokenIntrospection.withClaims(claims).active(true);
		}
		else {
			tokenClaims = OAuth2TokenIntrospection.builder(true);
		}

		tokenClaims.clientId(authorizedClient.getClientId());

		OAuth2Token token = authorizedToken.getToken();
		if (token.getIssuedAt() != null) {
			tokenClaims.issuedAt(token.getIssuedAt());
		}
		if (token.getExpiresAt() != null) {
			tokenClaims.expiresAt(token.getExpiresAt());
		}

		if (OAuth2AccessToken.class.isAssignableFrom(token.getClass())) {
			OAuth2AccessToken accessToken = (OAuth2AccessToken) token;
			tokenClaims.tokenType(accessToken.getTokenType().getValue());
		}

		return tokenClaims.build();
	}

	private static Map<String, Object> convertClaimsIfNecessary(Map<String, Object> claims) {
		Map<String, Object> convertedClaims = new HashMap<>(claims);

		Object value = claims.get(OAuth2TokenIntrospectionClaimNames.ISS);
		if (value != null && !(value instanceof URL)) {
			URL convertedValue = convertToUrl(value);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, convertedValue);
			}
		}

		value = claims.get(OAuth2TokenIntrospectionClaimNames.SCOPE);
		if (value != null && !(value instanceof List)) {
			Object convertedValue = ClaimConversionService.getSharedInstance()
					.convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, convertedValue);
			}
		}

		value = claims.get(OAuth2TokenIntrospectionClaimNames.AUD);
		if (value != null && !(value instanceof List)) {
			Object convertedValue = ClaimConversionService.getSharedInstance()
					.convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, convertedValue);
			}
		}

		return convertedClaims;
	}

	private static URL convertToUrl(Object value) {
		// ObjectToURLConverter uses toString (would work) and silently swallows the exception
		if (value instanceof URI uri) {
			try {
				return uri.toURL();
			}
			catch (MalformedURLException ex) {
				log.error("Cannot convert URI={} to URL message={}", uri, ex.getMessage());
				return null;
			}
		}
		return ClaimConversionService.getSharedInstance()
				.convert(value, URL.class);
	}

}
