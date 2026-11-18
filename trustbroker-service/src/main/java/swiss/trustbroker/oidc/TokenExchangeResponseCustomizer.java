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

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.jackson.ObjectMapperFactory;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

@AllArgsConstructor
@Slf4j
public class TokenExchangeResponseCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	// For generic claim-string JSON parsing (secured: polymorphic types restricted to java.lang/java.util)
	private static final JsonMapper JSON_MAPPER = ObjectMapperFactory.securedObjectMapper();

	private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

	private static final TypeReference<List<Map<String, Object>>> LIST_MAP_TYPE = new TypeReference<>() {};

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties properties;

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcAuditService auditService;

	@Override
	public void customize(JwtEncodingContext context) {
		// Normalize time claims
		Instant now = Instant.now();
		context.getClaims().claim(OidcUtil.OIDC_ISSUED_AT, now.getEpochSecond());
		context.getClaims().claim(OidcUtil.OIDC_NOT_BEFORE, now);

		var clientId = context.getRegisteredClient().getClientId();
		Optional<OidcClient> oidcClientOptional = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		if (oidcClientOptional.isEmpty()) {
			throw new TechnicalException("Missing OIDC client configuration for=" + clientId);
		}
		var tokenTimeToLiveMin = oidcClientOptional.get().getOidcSecurityPolicies().getTokenTimeToLiveMin();
		var tokenTimeToLive = tokenTimeToLiveMin != null ?
				tokenTimeToLiveMin * 60L : properties.getSecurity().getTokenLifetimeSec();
		context.getClaims().claim(OidcUtil.OIDC_EXPIRATION_TIME, now.plusSeconds(tokenTimeToLive).getEpochSecond());

		// Normalize audience
		Object aud = context.getClaims().build().getClaim(OidcUtil.OIDC_AUDIENCE);
		if (aud instanceof Collection<?>) {
			List<String> audience = new ArrayList<>();
			for (Object o : (Collection<?>) aud) {
				audience.add(String.valueOf(o));
			}
			context.getClaims().claim(OidcUtil.OIDC_AUDIENCE, audience);
		}
		else if (aud != null) {
			context.getClaims().claim(OidcUtil.OIDC_AUDIENCE, List.of(String.valueOf(aud)));
		}

		Object iss = context.getClaims().build().getClaim(OidcUtil.OIDC_ISSUER);
		if (iss instanceof URL url) {
			context.getClaims().claim(OidcUtil.OIDC_ISSUER, url.toString());
		}
		else if (iss instanceof URI uri) {
			context.getClaims().claim(OidcUtil.OIDC_ISSUER, uri.toString());
		}
		else if (iss != null) {
			context.getClaims().claim(OidcUtil.OIDC_ISSUER, String.valueOf(iss));
		}

		var kid = JwkUtil.getKeyIdFromJwkSource(jwkSource);
		addKeyIdFromJwkSource(kid, context);

		addAttributesToContext(context);

		auditService.auditTokenClaims(clientId, context, kid, null, null, properties,
				HttpExchangeSupport.getRunningHttpSession(), HttpExchangeSupport.getRunningHttpRequest());
	}

	private static void addKeyIdFromJwkSource(String kid, JwtEncodingContext context) {
		if (kid != null) {
			context.getJwsHeader().keyId(kid);
		}
	}
	private static void addAttributesToContext(JwtEncodingContext context) {
		Object tokenData = getTokenAttributes(context);
		if (tokenData == null) {
			return;
		}
		if (!(tokenData instanceof Map<?, ?> tokenMap)) {
			return;
		}

		tokenMap.forEach((key, value) -> addAttributeToContext(context, key, value));
	}

	private static void addAttributeToContext(JwtEncodingContext context, Object key, Object value) {
		if (!(key instanceof String keyValue)) {
			return;
		}
		if (value == null) {
			return;
		}
		if (value instanceof Instant instantValue) {
			context.getClaims().claim(keyValue, instantValue.getEpochSecond());
		}
		else if (value instanceof Date dateValue) {
			context.getClaims().claim(keyValue, dateValue.toInstant().getEpochSecond());
		}
		else if (value instanceof String stringValue) {
			// Attempt to deserialize back JSON-encoded objects (Map or List of Maps)
			context.getClaims().claim(keyValue, tryParseJson(stringValue));
		}
		else if (value instanceof Number || value instanceof Boolean) {
			context.getClaims().claim(keyValue, value);
		}
		else if (value instanceof Collection<?> values) {
			List<String> safe = values.stream().map(String::valueOf).toList();
			if (safe.size() == 1) {
				Object parsed = tryParseJson(safe.getFirst());
				// Only unwrap if it actually deserialized to an object/list - otherwise keep original list
				context.getClaims().claim(keyValue, parsed != safe.getFirst() ? parsed : safe);
			}
			else {
				context.getClaims().claim(keyValue, safe);
			}
		}
		// "cnf" claim and other raw maps pass through unchanged
		else if (value instanceof Map<?, ?> map) {
			context.getClaims().claim(keyValue, map);
		}
	}

	/**
	 * If the string is a JSON object or array of objects, deserialize it back to the corresponding Java object.
	 * Otherwise, return the string unchanged.
	 */
	static Object tryParseJson(String value) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		if (trimmed.isEmpty()) {
			return value;
		}
		if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
			return value;
		}

		// Only treat arrays as JSON payloads when they start with an object: [{...}] (with optional whitespace)
		if (trimmed.startsWith("[") && !trimmed.matches("^\\[\\s*\\{.*")) {
			return value;
		}

		// Reject polymorphic payloads
		if (trimmed.contains("@class") || trimmed.contains("@type")) {
			log.warn("Rejected polymorphic JSON payload");
			return value;
		}
		try {
			if (trimmed.startsWith("{")) {
				return JSON_MAPPER.readValue(trimmed, MAP_TYPE);
			}
			return JSON_MAPPER.readValue(trimmed, LIST_MAP_TYPE);
		}
		catch (Exception e) {
			log.debug("String claim is not JSON, keeping as-is: {} {}", e.getClass().getSimpleName(), e.getMessage());
			return value;
		}
	}

	private static Object getTokenAttributes(JwtEncodingContext context) {
		Object authorization = context.getAuthorizationGrant();
		if (authorization instanceof OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthenticationToken) {
			return tokenExchangeAuthenticationToken.getDetails();
		}
		if (context.getAuthorization() != null && context.getAuthorization().getAttributes() != null) {
			return context.getAuthorization().getAttributes();
		}
		return null;
	}
}
