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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class RestResponseHandlerTest {

	private final RestResponseHandler responseHandler = new RestResponseHandler();
	private final ObjectMapper objectMapper = new ObjectMapper();

	private JsonNode json(String payload) {
		try {
			return objectMapper.readTree(payload);
		}
		catch (Exception ex) {
			fail("Invalid test JSON payload", ex);
			return null;
		}
	}

	@Test
	void mapResponseWithClaimsSelectionAndQueryResult() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "12345",
				      "emails": ["user1@trustbroker.swiss", "user2@trustbroker.swiss"],
				      "groups": ["admin", "staff"],
				      "someProp": "ignoredValue"
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		// Relying party with claims selection
		var relyingParty = RelyingParty.builder()
				.claimsSelection(AttributesSelection.builder()
						.definitions(List.of(
								// valid source: IDM
								Definition.builder().name("uid").storeMapper("/id").source("IDM").build(),
								// valid source: IDM:REST
								Definition.builder().name("mail").storeMapper("/emails").source("IDM:REST").build(),
								// invalid source: should be ignored
								Definition.builder().name("prop").storeMapper("/someProp").source("PROPS").build()
						))
						.build())
				.build();

		// IDM Query attributes (user details selection)
		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("roles").storeMapper("/groups").build()
						))
						.build())
				.build();

		var result = responseHandler.mapResponse(jsonNode, relyingParty, idmRequest, "/Resources");

		assertEquals(1, result.size());
		assertEquals(List.of("12345"), result.getFirst().get("uid"));
		assertEquals(List.of("user1@trustbroker.swiss", "user2@trustbroker.swiss"), result.getFirst().get("mail"));
		assertEquals(List.of("admin", "staff"), result.getFirst().get("roles"));
		// Assert that the source="PROPS" attribute was not parsed
		assertNull(result.getFirst().get("prop"));
	}

	@Test
	void mapResponseUsesAttributeSelectionWhenNoExplicitMappingExists() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "userName": "user.test"
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);
		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(Definition.builder().name("userName").build()))
						.build())
				.build();

		var result = responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources");

		assertEquals(1, result.size());
		assertEquals(List.of("user.test"), result.getFirst().get("userName"));
	}

	@Test
	void mapResponseAbsoluteJsonPointerWithoutResponseRootPath() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "1",
				      "userName": "test@example.com",
				      "active": true,
				      "name": {
				        "givenName": "Test",
				        "familyName": "Example"
				      }
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("lastName")
										.storeMapper("/Resources/0/name/familyName")
										.build()
						))
						.build())
				.build();

		// No subResource – absolute pointer in storeMapper navigates from root
		var result = responseHandler.mapResponse(jsonNode, null, idmRequest, null);

		assertEquals(1, result.size());
		assertEquals(List.of("Example"), result.getFirst().get("lastName"));
	}

	@Test
	void mapResponseWithNestedGroupCombinatorReturnsEmptyResult() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "1",
				      "groups": [
				        { "value": "g1", "display": "admin" },
				        { "value": "g2", "display": "staff" }
				      ]
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("displayName").storeMapper("/groups[]/value:/display").build()
						))
						.build())
				.build();

		var result = responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources");
		assertTrue(result.isEmpty());
	}

	@Test
	void collectScalarValuesAcceptsListOfStrings() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "1",
				      "groups": ["admin", "staff"]
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("rawGroups").storeMapper("/groups").build()
						))
						.build())
				.build();

		var result = responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources");
		assertEquals(1, result.size());
		assertEquals(List.of("admin", "staff"), result.getFirst().get("rawGroups"));
	}

	@Test
	void collectScalarValuesThrowsForObjectElementsInList() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "1",
				      "groups": [
				        { "value": "g1", "display": "admin" },
				        { "value": "g2", "display": "staff" }
				      ]
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("rawGroups").storeMapper("/groups").build()
						))
						.build())
				.build();

		assertThrows(TechnicalException.class,
				() -> responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources"));
	}

	@Test
	void collectScalarValuesThrowsForNonStringOrList() {
		var jsonResponse = """
				{
				  "Resources": [
				    {
				      "id": "1",
				      "active": true
				    }
				  ]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("active").storeMapper("/active").build()
						))
						.build())
				.build();

		assertThrows(TechnicalException.class,
				() -> responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources"));
	}

	@Test
	void mapResponseFallsBackWhenConfiguredResponseRootPathIsMissing() {
		var jsonResponse = """
				{
				  "id": "1",
				  "groups": ["admin", "staff"]
				}
				""";
		var jsonNode = json(jsonResponse);

		var idmRequest = IdmQuery.builder()
				.name("REST")
				.userDetailsSelection(AttributesSelection.builder()
						.definitions(List.of(
								Definition.builder().name("rawGroups").storeMapper("/groups").build()
						))
						.build())
				.build();

		// subResource "/Resources" is configured but missing from response – falls back to root object
		var result = responseHandler.mapResponse(jsonNode, null, idmRequest, "/Resources");
		assertEquals(1, result.size());
		assertEquals(List.of("admin", "staff"), result.getFirst().get("rawGroups"));
	}

}
