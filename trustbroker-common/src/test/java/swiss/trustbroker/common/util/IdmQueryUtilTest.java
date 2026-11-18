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

package swiss.trustbroker.common.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.exception.TechnicalException;

class IdmQueryUtilTest {

	private static final String UNDEF = "UNDEF";

	private record TestAttributeName(String name, String namespaceUri, String source) implements AttributeName {

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getAltName() {
			return null;
		}

		@Override
		public String getNamespaceUri() {
			return namespaceUri;
		}

		@Override
		public List<String> getOidcNameList() {
			return Collections.emptyList();
		}

		@Override
		public String getSource() {
			return source;
		}
	}

	@Test
	void isIdmClaim() {
		assertTrue(IdmQueryUtil.isIdmClaim("IDM:REST:mail"));
		assertTrue(IdmQueryUtil.isIdmClaim("LIST:IDM:LDAP:memberOf"));
		assertFalse(IdmQueryUtil.isIdmClaim("PROPS:mail"));
		assertFalse(IdmQueryUtil.isIdmClaim("IDM"));
	}

	@ParameterizedTest
	@MethodSource
	void resolveServiceName(String connection, String store, String expectedServiceName) {
		var idmRequest = mock(IdmRequest.class);
		when(idmRequest.getConnection()).thenReturn(connection);
		when(idmRequest.getStore()).thenReturn(store);

		var serviceName = IdmQueryUtil.resolveStoreName(idmRequest, "RP_ID");

		assertEquals(expectedServiceName, serviceName);
	}

	static Object[][] resolveServiceName() {
		return new Object[][] {
				{ "rest_service", "ignored_store", "rest_service" },
				{ null, "ldap_store", "ldap_store" },
				{ "", "ldap_store", "ldap_store" }
		};
	}

	@Test
	void resolveServiceNameFallsBackToStoreForLegacyIdmRequestImplementation() {
		IdmRequest idmRequest = new IdmRequest() {
			@Override
			public String getId() {
				return "id";
			}

			@Override
			public String getName() {
				return "name";
			}

			@Override
			public String getStore() {
				return "ldap_store";
			}

			@Override
			public Integer getOrder() {
				return null;
			}

			@Override
			public AttributeName getIssuerNameIdAttribute() {
				return null;
			}

			@Override
			public AttributeName getSubjectNameIdAttribute() {
				return null;
			}

			@Override
			public String getClientExtId() {
				return null;
			}

			@Override
			public String getAppFilter() {
				return null;
			}

			@Override
			public String getSubResource() {
				return null;
			}

			@Override
			public boolean isFetchActiveOnly() {
				return false;
			}

			@Override
			public List<AttributeName> getAttributeSelection() {
				return Collections.emptyList();
			}

			@Override
			public String getUserStatusPolicy() {
				return null;
			}
		};


		var serviceName = IdmQueryUtil.resolveStoreName(idmRequest, "RP_ID");

		assertEquals("ldap_store", serviceName);
	}

	@Test
	void resolveServiceNameThrowsWhenBothConnectionAndStoreEmpty() {
		var idmRequest = mock(IdmRequest.class);
		when(idmRequest.getConnection()).thenReturn(null);
		when(idmRequest.getStore()).thenReturn(null);

		var ex = assertThrows(TechnicalException.class,
				() -> IdmQueryUtil.resolveStoreName(idmRequest, "RP_ID"));

		assertEquals("Missing IDMQuery.connection or IDMQuery.store for rp=RP_ID: required to resolve service name",
				ex.getInternalMessage());
	}

	@Test
	void isPropertiesClaim() {
		assertTrue(IdmQueryUtil.isPropertiesClaim("PROPS:mail"));
		assertTrue(IdmQueryUtil.isPropertiesClaim("LIST:PROPS:mail"));
		assertFalse(IdmQueryUtil.isPropertiesClaim("IDM:REST:mail"));
		assertFalse(IdmQueryUtil.isPropertiesClaim("PROPS"));
	}

	@Test
	void getAttributeFromListMap() {
		var attrs = List.of(
				Map.of("roles", List.of("admin")),
				Map.of("mail", List.of("user@example.org"), "roles", List.of("staff"))
		);

		var values = IdmQueryUtil.getAttributeFromListMap("roles", attrs);

		assertEquals(List.of("admin", "staff"), values);
	}

	@Test
	void getUserDetailsFromCurrentStore() {
		var previousResults = List.of(Map.of("roles", List.of("admin", "staff")));

		var values = IdmQueryUtil.getUserDetails("IDM:LDAP:roles", previousResults, null, "LDAP", UNDEF);

		assertEquals(List.of("admin", "staff"), values);
	}

	@Test
	void getUserDetailsFromPreviousResultsOnlyAppliesToLdapStore() {
		// previous results are only consulted when the current store is LDAP
		var previousResults = List.of(Map.of("roles", List.of("admin", "staff")));

		var values = IdmQueryUtil.getUserDetails("IDM:REST:roles", previousResults, null, "REST", UNDEF);

		assertEquals(List.of(UNDEF), values);
	}

	@Test
	void getUserDetailsPrefersPreviousResultsOverSourceMatchForLdapStoreWhenNonEmpty() {
		// for the LDAP store, a non-empty attributeNameListMap is tried first, even if a source match also exists
		var key = attributeName("roles", "urn:test:roles", "IDM:LDAP");
		var result = IdmResult.builder().userDetails(Map.of(key, List.of("fromSource"))).build();
		var previousResults = List.of(Map.of("roles", List.of("fromPrevious")));

		var values = IdmQueryUtil.getUserDetails("IDM:LDAP:roles", previousResults, result, "LDAP", UNDEF);

		assertEquals(List.of("fromPrevious"), values);
	}

	@Test
	void getUserDetailsFallsBackToSourceMatchWhenPreviousResultsDoNotContainClaimForLdapStore() {
		// for the LDAP store, if the claim is not present in the (non-empty) attributeNameListMap, fall back to source match
		var key = attributeName("mail", "urn:test:mail", "IDM:LDAP");
		var result = IdmResult.builder().userDetails(Map.of(key, List.of("user@example.org"))).build();
		var previousResults = List.of(Map.of("roles", List.of("admin")));

		var values = IdmQueryUtil.getUserDetails("IDM:LDAP:mail", previousResults, result, "LDAP", UNDEF);

		assertEquals(List.of("user@example.org"), values);
	}

	@Test
	void getUserDetailsFromOtherStoreAndFallbackToUndefinedForNullValues() {
		var key = attributeName("mail", "urn:test:mail", "IDM:LDAP");
		var result = IdmResult.builder()
				.userDetails(Map.of(key, Arrays.asList("user@example.org", "user@example.org", null)))
				.build();

		var values = IdmQueryUtil.getUserDetails("IDM:LDAP:mail", List.of(), result, "REST", UNDEF);

		assertEquals(List.of("user@example.org", UNDEF), values);
	}

	@Test
	void getUserDetailsStripsListPrefixFromSource() {
		var key = attributeName("mail", "urn:test:mail", "IDM");
		var result = IdmResult.builder()
				.userDetails(Map.of(key, List.of("user@example.org")))
				.build();

		var values = IdmQueryUtil.getUserDetails("LIST:IDM:mail", List.of(), result, "REST", UNDEF);

		assertEquals(List.of("user@example.org"), values);
	}

	@Test
	void getUserDetailsReturnsUndefinedWhenNotFound() {
		var key = attributeName("uid", "urn:test:uid", "IDM:LDAP");
		var result = IdmResult.builder().userDetails(Map.of(key, List.of("12345"))).build();

		var values = IdmQueryUtil.getUserDetails("IDM:LDAP:mail", List.of(), result, "REST", UNDEF);

		assertEquals(List.of(UNDEF), values);
	}

	@Test
	void getPropertiesByNameWithDistinct() {
		var byName = attributeName("costCenter", "urn:test:costCenter", null);
		var result = IdmResult.builder()
				.properties(new LinkedHashMap<>(Map.of(
						byName, List.of("cc1", "cc1")
				)))
				.build();

		var byNameValues = IdmQueryUtil.getProperties("PROPS:costCenter", result, UNDEF);

		assertEquals(List.of("cc1"), byNameValues);
	}

	@Test
	void getPropertiesUnknownNamespaceReturnsUndefined() {
		var byName = attributeName("costCenter", "urn:test:costCenter", null);
		var result = IdmResult.builder()
				.properties(Map.of(byName, List.of("cc1")))
				.build();

		var values = IdmQueryUtil.getProperties("PROPS:unknownNamespace", result, UNDEF);

		assertEquals(List.of(UNDEF), values);
	}

	@Test
	void getPropertiesReturnsUndefinedWhenResultEmpty() {
		assertEquals(List.of(UNDEF), IdmQueryUtil.getProperties("PROPS:costCenter", null, UNDEF));
		assertEquals(List.of(UNDEF), IdmQueryUtil.getProperties("PROPS:costCenter", IdmResult.builder().build(), UNDEF));
	}

	@Test
	void getPlaceholderValuesRoutesToSubjectNameIdAndAttributeAndIdmAndProps() {
		var cpResponse = mock(CpResponseData.class);
		when(cpResponse.getNameId()).thenReturn("subject-123");
		when(cpResponse.getAttribute("email")).thenReturn("user@example.org");

		var previousResults = List.of(Map.of("roles", List.of("admin")));
		var propKey = attributeName("department", "urn:test:department", null);
		var result = IdmResult.builder().properties(Map.of(propKey, List.of("IT"))).build();

		assertEquals(List.of(), IdmQueryUtil.getPlaceholderValues(null, cpResponse, previousResults, result, "LDAP", UNDEF));
		assertEquals(List.of("subject-123"), IdmQueryUtil.getPlaceholderValues("subjectNameId", cpResponse, previousResults, result, "LDAP", UNDEF));
		assertEquals(List.of("user@example.org"), IdmQueryUtil.getPlaceholderValues("email", cpResponse, previousResults, result, "LDAP", UNDEF));
		assertEquals(List.of("admin"), IdmQueryUtil.getPlaceholderValues("IDM:LDAP:roles", cpResponse, previousResults, result, "LDAP", UNDEF));
		assertEquals(List.of("admin"), IdmQueryUtil.getPlaceholderValues("LIST:IDM:LDAP:roles", cpResponse, previousResults, result, "LDAP", UNDEF));
		assertEquals(List.of("IT"), IdmQueryUtil.getPlaceholderValues("PROPS:department", cpResponse, previousResults, result, "LDAP", UNDEF));
	}

	private static AttributeName attributeName(String name, String namespace, String source) {
		return new TestAttributeName(name, namespace, source);
	}

}

