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

package swiss.trustbroker.ldap.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.naming.directory.SearchControls;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest(classes = { LdapStoreClient.class })
@TestPropertySource(properties = "trustbroker.config.ldap.enabled=true")
class LdapStoreClientTest {

	private static final String SUBJECT_NAME_ID = "subjectNameId";

	@MockitoBean
	LdapTemplate ldapTemplate;

	@MockitoBean(name = "ldapTemplates")
	Map<String, Supplier<LdapTemplate>> ldapTemplates;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@Autowired
	LdapStoreClient ldapClient;

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withUserConfiguration(LdapStoreClient.class);

	@Test
	void ldapClientBeanIsNotCreatedWhenLdapDisabled() {
		contextRunner.run(context -> {
			assertEquals(0, context.getBeanNamesForType(LdapStoreClient.class).length);
		});
	}

	@Test
	void getLdapAttributesTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		var idmRequests = givemIdmLookup(base);
		Supplier<LdapTemplate> templateSupplier = () -> ldapTemplate;
		doReturn(templateSupplier).when(ldapTemplates).get(any());

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).build();
		var ldapResult = ldapClient.search(rpConfig, cpResponse, idmRequests, unprocessedAttributes, result);
		assertEquals(2, ldapResult.size());
	}

	private static IdmQuery givemIdmLookup(String base) {
		return IdmQuery.builder().store("LDAP").name("LDAP").appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build();
	}

	private static List<Map<String, List<String>>> givenLdapAttributes() {
		List<Map<String, List<String>>> ldapAttributes = new ArrayList<>();
		Map<String, List<String>> attribute1 = new HashMap<>();
		attribute1.put("uid", List.of("uid1"));
		attribute1.put("mail", List.of("mail1"));
		ldapAttributes.add(attribute1);
		Map<String, List<String>> attribute2 = new HashMap<>();
		attribute2.put("uid", List.of("uid2"));
		attribute2.put("mail", List.of("mail2"));
		ldapAttributes.add(attribute2);
		return ldapAttributes;
	}

	@Test
	void getQueryBaseTest() {
		var rpConfig = RelyingParty.builder().id("relyingPartyId").build();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapClient.getQueryBase(null, rpConfig));
		assertThat(ex.getInternalMessage(), containsString("Missing subResource"));

		assertEquals("subresource", ldapClient.getQueryBase("subresource", rpConfig));
	}

	@Test
	void queryFilterFormatterTest() {
		var cpResponse = givenCpResponse();
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).build();
		var ex = assertThrows(TechnicalException.class,
				() -> ldapClient.queryFilterFormatter(null, cpResponse, "RP_ID", unprocessedAttributes, result));
		assertThat(ex.getInternalMessage(), containsString("AppFilter is null or empty"));

		assertEquals("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=uid)(attribute=attribute)))", cpResponse, "RP_ID", unprocessedAttributes, result));

		assertEquals("(&amp;(app=app1)(|(uid=UNDEF)(attribute=attribute)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:unknown})(attribute=${attribute})))", cpResponse, "RP_ID", unprocessedAttributes, result));

		assertEquals("(&amp;(app=app1)(|(uid=UNDEF)(id=UNDEF)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:unknown})(id=${unknownAttr})))", cpResponse, "RP_ID", unprocessedAttributes, result));

		assertEquals("(&amp;(app=app1)(|(uid=UNDEF)(attribute=\\2a)(value=\\29\\28test=\\2a)))",
				ldapClient.queryFilterFormatter("(&amp;(app=app1)(|(uid=${IDM:unknown})(attribute=${wildcard})"
						+ "(value=${injection})))", cpResponse, "RP_ID", unprocessedAttributes, result));
	}

	@Test
	void getEncodedPlaceHolderValueTest() {
		var valuesWithNullFirst = new ArrayList<String>();
		valuesWithNullFirst.add(null);
		valuesWithNullFirst.add("uid2");
		assertEquals("uid1", LdapStoreClient.getEncodedPlaceHolderValue("uid", List.of("uid1", "uid2"), "UNDEF"));
		assertEquals("uid2", LdapStoreClient.getEncodedPlaceHolderValue("uid", List.of("uid2"), "UNDEF"));
		assertEquals("UNDEF", LdapStoreClient.getEncodedPlaceHolderValue("uid", valuesWithNullFirst, "UNDEF"));
		assertEquals("user\\5c123", LdapStoreClient.getEncodedPlaceHolderValue("escape", List.of("user\\123", "user2"), "UNDEF"));
		assertEquals("\\2a", LdapStoreClient.getEncodedPlaceHolderValue("wildcard", List.of("*", "value"), "UNDEF"));
		assertEquals("(uid=uid1)", LdapStoreClient.getEncodedPlaceHolderValue("LIST:IDM:query:uid", List.of("uid1"), "UNDEF"));
		assertEquals("(uid=uid1)(uid=uid2)", LdapStoreClient.getEncodedPlaceHolderValue("LIST:IDM:query:uid", List.of("uid1", "uid2"), "UNDEF"));
		assertEquals("(uid=user\\5c123)(uid=\\2a)", LdapStoreClient.getEncodedPlaceHolderValue("LIST:IDM:query:uid", List.of("user\\123", "*"), "UNDEF"));
		List<String> noValues = Collections.emptyList();
		var ex = assertThrows(TechnicalException.class,
				() -> LdapStoreClient.getEncodedPlaceHolderValue("uid", noValues, "UNDEF"));
		assertThat(ex.getInternalMessage(), containsString("Unsupported placeholder values"));
	}

	@Test
	void getPlaceholderValueTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();

		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).properties(givenUserDetails()).build();
		assertEquals(List.of(), ldapClient.getPlaceholderValues(null, cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("NAME_ID"), ldapClient.getPlaceholderValues(SUBJECT_NAME_ID, cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("uid"), ldapClient.getPlaceholderValues("IDM:uid", cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("attribute"), ldapClient.getPlaceholderValues("attribute", cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("UNDEF"), ldapClient.getPlaceholderValues("LIST:IDM:unknown", cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("property1", "property2"), ldapClient.getPlaceholderValues("PROPS:property", cpResponse, unprocessedAttributes, result));
		assertEquals(List.of("property1", "property2"), ldapClient.getPlaceholderValues("LIST:PROPS:property", cpResponse, unprocessedAttributes, result));

		// LIST placeholder resolved from attributeNameListMap
		Map<String, List<String>> listEntry1 = new HashMap<>();
		listEntry1.put("uid", List.of("uid1", "uid2"));
		Map<String, List<String>> listEntry2 = new HashMap<>();
		listEntry2.put("uid", List.of("uid3", "uid4"));
		unprocessedAttributes.add(listEntry1);
		unprocessedAttributes.add(listEntry2);
		assertEquals(List.of("uid1", "uid2", "uid3", "uid4"), ldapClient.getPlaceholderValues("LIST:IDM:LDAP:uid", cpResponse, unprocessedAttributes, result));

		// LIST placeholder with unknown attribute falls back to UNDEF
		assertEquals(List.of("UNDEF"), ldapClient.getPlaceholderValues("LIST:IDM:queryName:unknownAttr", cpResponse, unprocessedAttributes, result));
	}

	@Test
	void getLdapAttributesWithConnectionAttributeTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		var idmRequests = IdmQuery.builder()
				.connection("LDAP")
				.appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build();
		Supplier<LdapTemplate> templateSupplier = () -> ldapTemplate;
		doReturn(templateSupplier).when(ldapTemplates).get("LDAP");

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).build();
		var ldapResult = ldapClient.search(rpConfig, cpResponse, idmRequests, unprocessedAttributes, result);
		assertEquals(2, ldapResult.size());
	}

	@Test
	void getLdapAttributesWithConnectionTakingPrecedenceOverStoreTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		// connection should take precedence over store
		var idmRequests = IdmQuery.builder()
				.store("ignored_store")
				.connection("LDAP")
				.appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build();
		Supplier<LdapTemplate> templateSupplier = () -> ldapTemplate;
		doReturn(templateSupplier).when(ldapTemplates).get("LDAP");

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).build();
		var ldapResult = ldapClient.search(rpConfig, cpResponse, idmRequests, unprocessedAttributes, result);
		assertEquals(2, ldapResult.size());
	}

	@Test
	void getLdapAttributesFallsBackToStoreWhenConnectionEmptyTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var cpResponse = givenCpResponse();
		var profileSelection = ProfileSelection.builder().enabled(true).mode(ProfileSelectionMode.INTERACTIVE).profileSelector("mail").build();
		var rpConfig = RelyingParty.builder().id("relyingPartyId").profileSelection(profileSelection).build();
		String base = "base";
		var idmRequests = IdmQuery.builder()
				.store("LDAP")
				.appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute}))").subResource(base).build();
		Supplier<LdapTemplate> templateSupplier = () -> ldapTemplate;
		doReturn(templateSupplier).when(ldapTemplates).get("LDAP");

		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq(base), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));
		List<Map<String, List<String>>> unprocessedAttributes = new LinkedList<>();
		IdmResult result = IdmResult.builder().userDetails(givenUserDetails()).build();
		var ldapResult = ldapClient.search(rpConfig, cpResponse, idmRequests, unprocessedAttributes, result);
		assertEquals(2, ldapResult.size());
	}

	@Test
	void getEncodedPlaceHolderValueRejectsMalformedListPlaceholder() {
		var ex = assertThrows(TechnicalException.class,
				() -> LdapStoreClient.getEncodedPlaceHolderValue("LIST:IDM:uid", List.of("uid1"), "UNDEF"));
		assertThat(ex.getInternalMessage(), containsString("Expected LIST placeholder format"));
	}

	@Test
	void searchUsesCaseInsensitiveTemplateLookupTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();

		var idmRequest = IdmQuery.builder()
				.store("ldap")
				.name("LDAP")
				.appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute})))")
				.subResource("base")
				.build();
		Supplier<LdapTemplate> templateSupplier = () -> ldapTemplate;
		doReturn(null).when(ldapTemplates).get("ldap");
		doReturn(Map.of("LDAP", templateSupplier).entrySet()).when(ldapTemplates).entrySet();
		doReturn(givenLdapAttributes()).when(ldapTemplate).search(eq("base"), any(), eq(SearchControls.SUBTREE_SCOPE), any(), any(LdapAttributeMapper.class));

		var ldapResult = ldapClient.search(RelyingParty.builder().id("relyingPartyId").build(), givenCpResponse(), idmRequest,
				new LinkedList<>(), IdmResult.builder().userDetails(givenUserDetails()).build());

		assertEquals(2, ldapResult.size());
	}

	@Test
	void searchThrowsWhenStoreIsUnknownTest() {
		var ldapConfig = new LdapStoreConfig(true, Map.of(), "UNDEF", ":");
		doReturn(ldapConfig).when(trustBrokerProperties).getLdap();
		doReturn(null).when(ldapTemplates).get("UNKNOWN");
		doReturn(Collections.emptySet()).when(ldapTemplates).entrySet();

		var ex = assertThrows(TechnicalException.class,
				() -> ldapClient.search(RelyingParty.builder().id("relyingPartyId").build(), givenCpResponse(),
						IdmQuery.builder().store("UNKNOWN").name("LDAP")
								.appFilter("(&amp;(app=app1)(|(uid=${IDM:uid})(attribute=${attribute})))")
								.subResource("base")
								.build(),
						new LinkedList<>(), IdmResult.builder().userDetails(givenUserDetails()).build()));
		assertThat(ex.getInternalMessage(), containsString("Unknown LDAP store 'UNKNOWN'"));
	}

	private Map<AttributeName, List<String>> givenUserDetails() {
		Map<AttributeName, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("uid").source("IDM").build(), List.of("uid"));
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("attribute").build(), List.of("attribute"));
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("wildcard").build(), List.of("*"));
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("escape").source("IDM").build(), List.of("user\\123"));
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("injection").build(), List.of(")(test=*"));
		attributeValueMap.put(SamlTestBase.TestAttributeName.builder().name("property").source("PROPS").build(), List.of("property1", "property2"));
		return attributeValueMap;
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(Definition.ofNameAndSource("uid", "IDM"), List.of("uid"));
		attributeValueMap.put(new Definition("attribute"), List.of("attribute"));
		attributeValueMap.put(new Definition("wildcard"), List.of("*"));
		attributeValueMap.put(new Definition("escape"), List.of("user\\123"));
		attributeValueMap.put(new Definition("injection"), List.of(")(test=*"));
		return CpResponse.builder()
						 .userDetails(attributeValueMap)
						 .attributes(attributeValueMap)
						 .nameId("NAME_ID")
						 .build();
	}
}
