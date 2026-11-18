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

package swiss.trustbroker.rest.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import io.micrometer.core.annotation.Timed;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.IdmQueryUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RestServiceEndpointConfig;
import swiss.trustbroker.config.dto.RestStoreConfig;
import tools.jackson.databind.JsonNode;

@Service
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.rest.enabled")
public class RestStoreClient {

	private final TrustBrokerProperties trustBrokerProperties;
	private final Map<String, WebClient> webClients;
	private final RestResponseHandler restResponseHandler;

	@Autowired
	public RestStoreClient(TrustBrokerProperties trustBrokerProperties,
	                       @Qualifier("restStoreWebClients") Map<String, WebClient> webClients,
	                       RestResponseHandler restResponseHandler) {
		this.trustBrokerProperties = trustBrokerProperties;
		this.webClients = webClients;
		this.restResponseHandler = restResponseHandler;
	}

	@Timed("rest")
	@Traced
	public List<Map<String, List<String>>> search(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
	                                              IdmRequest idmQuery, List<Map<String, List<String>>> attributes, IdmResult result) {
		var config = trustBrokerProperties.getRest();
		var storeName = resolveStoreName(idmQuery, relyingPartyConfig.getId(), config);
		var requestUri = buildRequestUri(idmQuery, cpResponse, attributes, result, relyingPartyConfig.getId(), config);
		log.info("IDM call ({}): issuer={} relyingPartyIssuerId={} store={} uri={}",
				ExternalStores.REST, cpResponse.getIssuerId(), relyingPartyConfig.getId(), storeName, requestUri);
		var webClient = resolveWebClient(storeName, relyingPartyConfig.getId());
		var endpoint = getConfiguredStoreEndpoint(config.getStores(), storeName, relyingPartyConfig.getId());
		var response = executeGet(endpoint, webClient, requestUri);
		if (response == null) {
			log.warn("IDM call ({}) failed without response payload for rp={} uri={}",
					ExternalStores.REST, relyingPartyConfig.getId(), requestUri);
			return List.of();
		}
		return restResponseHandler.mapResponse(response, relyingPartyConfig, idmQuery, idmQuery.getSubResource());
	}

	Integer resolveResponseTimeoutSec(RestServiceEndpointConfig endpoint) {
		var network = endpoint.getNetwork();
		return network != null ? network.getBackendResponseTimeoutSec() : null;
	}

	JsonNode executeGet(RestServiceEndpointConfig endpoint, WebClient webClient, URI requestUri) {
		var responseTimeout = Duration.ofSeconds(resolveResponseTimeoutSec(endpoint));
		try {
			if (responseTimeout != null) {
				return webClient.get()
				                .uri(requestUri)
				                .exchangeToMono(response ->
										response.statusCode().is2xxSuccessful()
												? response.bodyToMono(JsonNode.class)
												: Mono.empty()
								)
				                .timeout(responseTimeout)
				                .block();
			}
			else {
				return webClient.get()
				                .uri(requestUri)
				                .exchangeToMono(response ->
										response.statusCode().is2xxSuccessful()
												? response.bodyToMono(JsonNode.class)
												: Mono.empty()
								)
				                .block();
			}
		}
		catch (WebClientRequestException ex) {
			log.warn("IDM call ({}) failed for uri={} with message={}", ExternalStores.REST, requestUri, ex.getMessage());
			return null;
		}
	}

	URI buildRequestUri(IdmRequest idmQuery, CpResponseData cpResponse, List<Map<String, List<String>>> attributes,
	                    IdmResult result, String rpId, RestStoreConfig config) {
		var baseUrl = getBaseUrl(config, idmQuery, rpId);
		var requestUrl = baseUrl;
		if (StringUtils.isNotEmpty(idmQuery.getAppFilter())) {
			var filterParamValue = formatValueTemplate(idmQuery.getAppFilter(), cpResponse, attributes, result, rpId, config);
			if (baseUrl.endsWith("/") && filterParamValue.startsWith("/")) {
				requestUrl = baseUrl + filterParamValue.substring(1);
			}
			else if (filterParamValue.startsWith("?") || filterParamValue.startsWith("&")) {
				requestUrl = baseUrl + filterParamValue;
			}
			else if (!baseUrl.endsWith("/") && !filterParamValue.startsWith("/")) {
				requestUrl = baseUrl + "/" + filterParamValue;
			}
			else {
				requestUrl = baseUrl + filterParamValue;
			}
		}

		try {
			return new URI(requestUrl);
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException(String.format("Could not build REST request URL=%s", requestUrl), ex);
		}
	}

	private WebClient resolveWebClient(String storeName, String rpId) {
		var webClient = webClients.get(storeName);
		if (webClient != null) {
			return webClient;
		}
		// case-insensitive fallback
		for (var entry : webClients.entrySet()) {
			if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(storeName)) {
				return entry.getValue();
			}
		}
		throw new TechnicalException(String.format("No WebClient found for REST store '%s' rp=%s. Configured stores: %s",
				storeName, rpId, webClients.keySet()));
	}

	private String resolveStoreName(IdmRequest idmQuery, String rpId, RestStoreConfig config) {
		var stores = config.getStores();
		if (stores == null || stores.isEmpty()) {
			throw new TechnicalException("Missing REST stores configuration trustbroker.config.rest.stores");
		}
		return IdmQueryUtil.resolveStoreName(idmQuery, rpId);
	}

	private String getBaseUrl(RestStoreConfig config, IdmRequest idmQuery, String rpId) {
		if (config == null) {
			throw new TechnicalException("Missing REST configuration trustbroker.config.rest");
		}
		var stores = config.getStores();
		if (stores == null || stores.isEmpty()) {
			throw new TechnicalException("Missing REST stores configuration trustbroker.config.rest.stores");
		}
		var storeName = resolveStoreName(idmQuery, rpId, config);
		var endpoint = getConfiguredStoreEndpoint(stores, storeName, rpId);
		return validateBaseUrl(endpoint.getBaseUrl(), rpId, "trustbroker.config.rest.stores." + storeName + ".baseUrl");
	}

	private static RestServiceEndpointConfig getConfiguredStoreEndpoint(Map<String, RestServiceEndpointConfig> stores,
	                                                                    String storeName, String rpId) {
		if (StringUtils.isEmpty(storeName)) {
			throw new TechnicalException(String.format(
					"Missing IDMQuery.connection or IDMQuery.store for rp=%s: required to resolve trustbroker.config.rest.stores.<name>", rpId));
		}
		var endpoint = stores.get(storeName);
		if (endpoint != null) {
			return endpoint;
		}
		for (var entry : stores.entrySet()) {
			if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(storeName)) {
				return entry.getValue();
			}
		}
		Set<String> configuredNames = stores.keySet();
		throw new TechnicalException(String.format(
				"Unknown REST store '%s' for rp=%s. Configure trustbroker.config.rest.stores.%s or use one of: %s",
				storeName, rpId, storeName, configuredNames));
	}

	private static String validateBaseUrl(String baseUrl, String rpId, String configPath) {
		if (StringUtils.isEmpty(baseUrl)) {
			throw new TechnicalException(String.format("Missing REST endpoint URL for rp=%s HINT: Set %s", rpId, configPath));
		}
		if (baseUrl.contains("${")) {
			throw new TechnicalException(String.format(
					"Invalid REST baseUrl for rp=%s: placeholders are not allowed in %s, use IDMQuery.appFilter",
					rpId, configPath));
		}
		try {
			var uri = new URI(baseUrl);
			if (uri.getQuery() != null) {
				throw new TechnicalException(String.format(
						"Invalid REST baseUrl for rp=%s: query parameters are not allowed in %s, use IDMQuery.appFilter",
						rpId, configPath));
			}
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException(String.format("Could not parse REST baseUrl=%s", baseUrl), ex);
		}
		return baseUrl;
	}

	String formatValueTemplate(String template, CpResponseData cpResponse, List<Map<String, List<String>>> attributes,
	                           IdmResult result, String rpId, RestStoreConfig config) {
		if (template == null) {
			return null;
		}
		var undefined = config.getUndefined();
		var pattern = Pattern.compile(IdmQueryUtil.PLACEHOLDER_PATTERN);
		var matcher = pattern.matcher(template);
		List<String> placeholders = new ArrayList<>();
		while (matcher.find()) {
			placeholders.add(matcher.group(1));
		}
		Map<String, Object> params = new HashMap<>();
		for (var placeholder : placeholders) {
			var values = IdmQueryUtil.getPlaceholderValues(placeholder, cpResponse, attributes, result, ExternalStores.REST.name(), undefined);
			var resolvedValue = values.isEmpty() ? undefined : values.getFirst();
			params.put(placeholder, resolvedValue == null ? undefined : resolvedValue);
		}
		var formatted = StringSubstitutor.replace(template, params, "${", "}");
		if (formatted.contains("${")) {
			throw new TechnicalException(String.format("Unable to resolve placeholders in template='%s' for rp=%s", template, rpId));
		}
		return formatted;
	}

}
