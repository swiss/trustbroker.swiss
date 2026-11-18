/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
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

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Utility methods for the OAuth 2.0 Protocol Endpoints. Copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2EndpointUtils
 * That class is final, so we cannot subclass it.
 * The copying means we are tied to an internal class from Spring Authentication Server.
 * <p>
 * Original Javadoc:
 * Utility methods for the OAuth 2.0 Protocol Endpoints.
 *
 * @author Joe Grandja, Greg Li
 * @since 0.1.2
 */
@Slf4j
public class CustomOAuth2EndpointUtils {

	static final String ACCESS_TOKEN_REQUEST_ERROR_URI = CustomOAuth2ErrorCodes.ACCESS_TOKEN_REQUEST_ERROR_URI;

	private CustomOAuth2EndpointUtils(){}

	static MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameterMap.forEach((key, values) -> {
			String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
			// If not query parameter then it's a form parameter
			if (!queryString.contains(key) && values.length > 0) {
				for (String value : values) {
					parameters.add(key, value);
				}
			}
		});
		return parameters;
	}

	static void validateAndAddDPoPParametersIfAvailable(HttpServletRequest request,
														Map<String, Object> additionalParameters) {
		final String dPoPProofHeaderName = OAuth2AccessToken.TokenType.DPOP.getValue();
		String dPoPProof = request.getHeader(dPoPProofHeaderName);
		if (StringUtils.hasText(dPoPProof)) {
			if (Collections.list(request.getHeaders(dPoPProofHeaderName)).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, dPoPProofHeaderName, ACCESS_TOKEN_REQUEST_ERROR_URI);
			}
			else {
				additionalParameters.put("dpop_proof", dPoPProof);
				additionalParameters.put("dpop_method", request.getMethod());
				additionalParameters.put("dpop_target_uri", request.getRequestURL().toString());
			}
		}
	}

	static void throwError(String errorCode, String parameterName, String errorUri) {
		var description = "OAuth 2.0 Parameter: " + parameterName;
		var error = new OAuth2Error(errorCode, description, errorUri);
		log.error(description, error);
		throw new OidcExceptionHelper.OidcAuthenticationException(error, description);
	}

	static void throwErrorWithMessage(String errorCode, String errorMessage, String logMessage, String errorUri) {
		log.error(logMessage);
		var error = new OAuth2Error(errorCode, errorMessage, errorUri);
		throw new OidcExceptionHelper.OidcAuthenticationException(error, errorMessage);
	}
}
