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

import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.TxnSupport;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OidcCtxPropagator {

	// OAuth2/OIDC context to be propagated via redirects (including SAML POST)
	static String addAuthenticationContextParams(
			String location, HttpServletRequest request, TrustBrokerProperties properties, boolean fullContext) {
		var uriComponentsBuilder = UriComponentsBuilder.fromUriString(location);
		if (fullContext) {
			var acrValues = request.getParameter(OidcUtil.OIDC_ACR_VALUES);
			if (acrValues != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_ACR_VALUES, UriUtils.encode(acrValues, StandardCharsets.UTF_8));
			}
			var clientId = request.getParameter(OidcUtil.OIDC_CLIENT_ID);
			if (clientId != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_CLIENT_ID, UriUtils.encode(clientId, StandardCharsets.UTF_8));
			}
			var promptLogin = request.getParameter(OidcUtil.OIDC_PROMPT);
			if (promptLogin != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_PROMPT, UriUtils.encode(promptLogin, StandardCharsets.UTF_8));
			}
			var hrdHint = HrdSupport.getHrdHintParameter(request, properties);
			if (hrdHint != null) {
				uriComponentsBuilder.queryParam(properties.getHrdHintParameter(), UriUtils.encode(hrdHint, StandardCharsets.UTF_8));
			}
			var scopes = request.getParameter(OidcUtil.OIDC_SCOPE);
			if (scopes != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_SCOPE, UriUtils.encode(scopes, StandardCharsets.UTF_8));
			}
		}
		// optional since v1.16.0
		var txnId = TxnSupport.getRpTxnIdFromRequest(request, properties);
		if (txnId != null) {
			uriComponentsBuilder.queryParam(properties.getRpTxnIdParameter(), UriUtils.encode(txnId, StandardCharsets.UTF_8));
		}

		var ret = uriComponentsBuilder.build().toUriString();
		log.debug("Constructed redirectUrl='{}' with parameters from request context", ret);
		return ret;
	}

	// redirect from /authorize to /saml2/authenticate (full context)
	public static String addOauth2AuthorizeContext(String location, HttpServletRequest request, TrustBrokerProperties properties) {
		if ( request.getRequestURI().endsWith(ApiSupport.SPRING_OAUTH2_AUTHORIZE_CTXPATH)) {
			return addAuthenticationContextParams(location, request, properties, true);
		}
		return location;
	}

	// SAML POST to /api/v1/saml
	// Most of the context is transferred via signed SAML2 AuthnRequest (see OidcAuthnRequestContextCustomizer), specifically:
	// - acr_values via AuthnRequest.RequestedAuthnContext.AuthnContextClassRef
	// - client_id via AuthnRequest.ProviderName
	// - hrd_hint via AuthnRequest.Scoping.IDPList
	// - prompt=login via AuthnRequest.ForceAuthn
	// Transferred therefore here are only:
	// - scope
	// - rp_txn_id (if configured)
	public static String addOauth2SamlPostContext(String location, HttpServletRequest request, TrustBrokerProperties properties) {
		if ( request.getRequestURI().startsWith(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH)) {
			return addAuthenticationContextParams(location, request, properties, false);
		}
		return location;
	}

}
