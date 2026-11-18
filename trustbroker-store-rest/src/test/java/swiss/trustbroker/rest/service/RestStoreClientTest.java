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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.IdmConfig;
import swiss.trustbroker.config.dto.RestServiceEndpointConfig;
import swiss.trustbroker.config.dto.RestStoreConfig;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.saml.dto.CpResponse;

class RestStoreClientTest {

	public static final List<Map<String, List<String>>> NO_ATTRIBUTES = List.of();

	private final TrustBrokerProperties trustBrokerProperties = mock(TrustBrokerProperties.class);
	private final Map<String, WebClient> webClients = new LinkedHashMap<>();
	private final RestResponseHandler responseHandler = new RestResponseHandler();
	private final RestStoreClient client = new RestStoreClient(trustBrokerProperties, webClients, responseHandler);

	private final RestStoreConfig restConfig = new RestStoreConfig();

	@BeforeEach
	void setup() {
		doReturn(restConfig).when(trustBrokerProperties).getRest();
		doReturn(new IdmConfig()).when(trustBrokerProperties).getIdm();
	}

	@Test
	void buildRequestUriResolvesConfiguredAndDynamicQueryParameters() {
		configureService("REST", "https://rest.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.connection("REST")
				.appFilter("/Users")
				.build();
		var cpResponse = givenCpResponse();

		var uri = client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig);

		assertEquals("https://rest.trustbroker.swiss/v2/Users", uri.toString());
	}

	@Test
	void formatValueTemplateResolvesIdmPlaceholderFromCurrentRestResults() {
		// previous results (attributeNameListMap) are only consulted for the LDAP store, and in production REST never
		// passes previous results (RestStoreService always calls search with List.of()). So for REST, the IDM:REST:xxx
		// placeholder must resolve from the current IdmResult's userDetails (matched by source), not from previousResults.
		restConfig.setUndefined("UNDEF");
		var cpResponse = givenCpResponse();
		var key = Definition.builder().name("employeeNumber").source("IDM:REST").build();
		var result = IdmResult.builder().userDetails(Map.of(key, List.of("12345"))).build();

		var formatted = client.formatValueTemplate("employeeNumber eq ${IDM:REST:employeeNumber}", cpResponse,
				NO_ATTRIBUTES, result, "RP_ID", restConfig);

		assertEquals("employeeNumber eq 12345", formatted);
	}

	@Test
	void formatValueTemplateDoesNotResolveIdmPlaceholderFromPreviousRestResults() {
		// REST store does not consult attributeNameListMap (previous results); that is LDAP-only behavior.
		restConfig.setUndefined("UNDEF");
		var cpResponse = givenCpResponse();
		List<Map<String, List<String>>> previousResults = List.of(Map.of("employeeNumber", List.of("12345")));

		var formatted = client.formatValueTemplate("employeeNumber eq ${IDM:REST:employeeNumber}", cpResponse,
				previousResults, new IdmResult(), "RP_ID", restConfig);

		assertEquals("employeeNumber eq UNDEF", formatted);
	}

	@Test
	void buildRequestUriRejectsPlaceholdersInBaseUrl() {
		configureService("REST", "https://rest.trustbroker.swiss/v2/users/${subjectNameId}");

		var idmQuery = IdmQuery.builder()
				.connection("REST")
				.build();
		var cpResponse = givenCpResponse();
		var result = new IdmResult();

		var ex = assertThrows(TechnicalException.class,
				() -> client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, result, "RP_ID", restConfig));

		assertThat(ex.getInternalMessage(), containsString("placeholders are not allowed"));
	}

	@Test
	void buildRequestUriRejectsQueryParametersInBaseUrl() {
		configureService("REST", "https://rest.trustbroker.swiss/v2/users?id=static");

		var idmQuery = IdmQuery.builder()
				.connection("REST")
				.build();
		var cpResponse = givenCpResponse();
		var result = new IdmResult();

		var ex = assertThrows(TechnicalException.class,
				() -> client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, result, "RP_ID", restConfig));

		assertThat(ex.getInternalMessage(), containsString("query parameters are not allowed"));
	}

	@Test
	void buildRequestUriResolvesQueryParametersInAppFilter() {
		configureService("REST", "https://rest.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.connection("REST")
				.appFilter("/users?id=${subjectNameId}")
				.build();
		var cpResponse = givenCpResponse();

		var uri = client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig);

		assertEquals("https://rest.trustbroker.swiss/v2/users?id=NAME_ID", uri.toString());
	}

	@Test
	void buildRequestUriResolvesNamedServiceFromIdmQueryConnection() {
		configureService("rest1", "https://rest1.trustbroker.swiss/v2");
		configureService("rest2", "https://rest2.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.connection("rest2")
				.appFilter("/users")
				.build();
		var cpResponse = givenCpResponse();

		var uri = client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig);

		assertEquals("https://rest2.trustbroker.swiss/v2/users", uri.toString());
	}

	@Test
	void buildRequestUriRejectsUnknownServiceName() {
		configureService("rest1", "https://rest1.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.connection("unknownService")
				.build();
		var cpResponse = givenCpResponse();

		var ex = assertThrows(TechnicalException.class,
				() -> client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig));

		assertThat(ex.getInternalMessage(), containsString("Unknown REST store"));
	}

	@Test
	void buildRequestUriIgnoresIdmQueryNameWhenConnectionIsSet() {
		configureService("rest1", "https://rest1.trustbroker.swiss/v2");
		configureService("rest2", "https://rest2.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.name("ignored")
				.connection("rest2")
				.appFilter("/users")
				.build();
		var cpResponse = givenCpResponse();

		var uri = client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig);

		assertEquals("https://rest2.trustbroker.swiss/v2/users", uri.toString());
	}

	@Test
	void buildRequestUriFallsBackToStoreWhenConnectionIsEmpty() {
		configureService("rest1", "https://rest1.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.store("rest1")
				.appFilter("/users")
				.build();
		var cpResponse = givenCpResponse();

		var uri = client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig);

		assertEquals("https://rest1.trustbroker.swiss/v2/users", uri.toString());
	}

	@Test
	void buildRequestUriRejectsWhenBothConnectionAndStoreAreEmpty() {
		configureService("rest1", "https://rest1.trustbroker.swiss/v2");

		var idmQuery = IdmQuery.builder()
				.build();
		var cpResponse = givenCpResponse();

		var ex = assertThrows(TechnicalException.class,
				() -> client.buildRequestUri(idmQuery, cpResponse, NO_ATTRIBUTES, new IdmResult(), "RP_ID", restConfig));

		assertThat(ex.getInternalMessage(), containsString("Missing IDMQuery.connection or IDMQuery.store"));
	}

	@Test
	void resolveResponseTimeoutSecUsesEndpointNetworkConfig() {
		var endpoint = new RestServiceEndpointConfig();
		assertEquals(30, client.resolveResponseTimeoutSec(endpoint));
		assertEquals(30, endpoint.getNetwork().getBackendConnectTimeoutSec());

		endpoint.getNetwork().setBackendResponseTimeoutSec(42);
		assertEquals(42, client.resolveResponseTimeoutSec(endpoint));

		endpoint.setNetwork(null);
		assertEquals(null, client.resolveResponseTimeoutSec(endpoint));
	}

	private void configureService(String name, String baseUrl) {
		var endpoint = new RestServiceEndpointConfig();
		endpoint.setBaseUrl(baseUrl);
		restConfig.getStores().put(name, endpoint);
		webClients.put(name, mock(WebClient.class));
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(new Definition("attribute"), List.of("external-user-id"));
		return CpResponse.builder()
				.userDetails(attributeValueMap)
				.attributes(attributeValueMap)
				.nameId("NAME_ID")
				.build();
	}

}
