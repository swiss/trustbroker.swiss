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

package swiss.trustbroker.rest;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.AuthenticationConfig;
import swiss.trustbroker.config.dto.AuthenticationMethod;
import swiss.trustbroker.config.dto.RestServiceEndpointConfig;

@Configuration
@ConditionalOnBooleanProperty("trustbroker.config.rest.enabled")
public class RestStoreConfiguration {

	@Bean(name = "restStoreWebClients")
	Map<String, WebClient> restStoreWebClients(TrustBrokerProperties trustBrokerProperties) {
		var config = trustBrokerProperties.getRest();
		var stores = config.getStores();
		if (stores == null || stores.isEmpty()) {
			throw new TechnicalException("Missing REST stores configuration trustbroker.config.rest.stores");
		}
		if (stores.size() > 3) {
			throw new TechnicalException("Maximum number of REST stores is 3 in trustbroker.config.rest.stores");
		}
		var proxyUri = trustBrokerProperties.getNetwork() != null ?
				WebUtil.getValidatedUri(trustBrokerProperties.getNetwork().getProxyUrl()) : null;
		Map<String, WebClient> clients = new LinkedHashMap<>();
		for (var entry : stores.entrySet()) {
			var store = entry.getKey();
			var endpoint = entry.getValue();
			clients.put(store, buildWebClient(store, endpoint, trustBrokerProperties.getKeystoreBasePath(), proxyUri));
		}
		return clients;
	}

	private static WebClient buildWebClient(String storeName, RestServiceEndpointConfig endpoint,
	                                        String keystoreBasePath, URI proxyUri) {
		if (endpoint == null || endpoint.getBaseUrl() == null || endpoint.getBaseUrl().isBlank()) {
			throw new TechnicalException(String.format(
					"Missing REST endpoint URL in trustbroker.config.rest.services.%s.baseUrl", storeName));
		}
		var uri = WebUtil.getValidatedUri(endpoint.getBaseUrl());
		if (uri == null) {
			throw new TechnicalException(String.format(
					"Invalid baseUrl=\"%s\" for trustbroker.config.rest.services.%s.baseUrl",
					endpoint.getBaseUrl(), storeName));
		}
		var authentication = endpoint.getAuthentication();
		if (authentication == null || authentication.getMethod() == null) {
			throw new TechnicalException(String.format(
					"Missing REST authentication method trustbroker.config.rest.services.%s.authentication.method", storeName));
		}
		var keystore = authentication.getMethod() == AuthenticationMethod.CERTIFICATE ? authentication.getKeystore() : null;
		var network = endpoint.getNetwork();
		var connectTimeout = network != null ? Duration.ofSeconds(network.getBackendConnectTimeoutSec()) : null;
		var httpClient = HttpUtil.createHttpClient(uri.getScheme(), endpoint.getTruststore(), keystore,
				keystoreBasePath, proxyUri, HttpClient.Version.HTTP_1_1, connectTimeout);
		var webClientBuilder = WebClient.builder()
		                                .clientConnector(new JdkClientHttpConnector(httpClient))
		                                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		var authorizationHeader = getAuthorizationHeader(authentication);
		if (authorizationHeader != null) {
			webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);
		}
		return webClientBuilder.build();
	}

	private static String getAuthorizationHeader(AuthenticationConfig authentication) {
		return switch (authentication.getMethod()) {
			case BASIC -> WebUtil.getBasicAuthorizationHeader(authentication.getUsername(), authentication.getPassword());
			case BEARER -> WebUtil.getBearerAuthorizationHeader(authentication.getBearerToken());
			case CERTIFICATE -> null;
			case NONE -> null;
		};
	}
}
