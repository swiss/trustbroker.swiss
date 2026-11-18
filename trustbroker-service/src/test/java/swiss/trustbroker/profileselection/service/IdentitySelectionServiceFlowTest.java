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

package swiss.trustbroker.profileselection.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionProperties;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.api.sessioncache.dto.SessionState;
import swiss.trustbroker.config.dto.AttributeProperties;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.util.ApiSupport;

class IdentitySelectionServiceFlowTest {

	@Test
	void doInitialProfileSelectionRedirectsForInteractiveMultiProfile() {
		var apiSupport = mock(ApiSupport.class);
		doReturn("https://tb.example.org/profile/ex-1").when(apiSupport).getProfileSelectionUrl("ex-1");
		var service = new TestIdentitySelectionService(apiSupport);

		var profileSelectionData = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties(ProfileSelectionMode.INTERACTIVE.name()))
				.exchangeId("ex-1")
				.build();

		var result = service.doInitialProfileSelection(profileSelectionData, relyingParty(),
				cpResponse(multiProfileAttributes()), sessionState("session-1"));

		assertEquals("https://tb.example.org/profile/ex-1", result.getRedirectUrl());
	}

	@Test
	void doSsoProfileSelectionRedirectsForInteractiveMultiProfile() {
		var apiSupport = mock(ApiSupport.class);
		doReturn("https://tb.example.org/profile/session-2").when(apiSupport).getProfileSelectionUrl("session-2");
		var service = new TestIdentitySelectionService(apiSupport);

		var profileSelectionData = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties(ProfileSelectionMode.INTERACTIVE.name()))
				.build();

		var result = service.doSsoProfileSelection(profileSelectionData, relyingParty(),
				cpResponse(multiProfileAttributes()), sessionState("session-2"));

		assertEquals("https://tb.example.org/profile/session-2", result.getRedirectUrl());
	}

	@Test
	void doSsoProfileSelectionSilentModeKeepsAttributesAndNoRedirect() {
		var service = new TestIdentitySelectionService(mock(ApiSupport.class));
		var attrs = multiProfileAttributes();

		var profileSelectionData = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties(ProfileSelectionMode.SILENT.name()))
				.build();

		var result = service.doSsoProfileSelection(profileSelectionData, relyingParty(), cpResponse(attrs),
				sessionState("session-3"));

		assertNull(result.getRedirectUrl());
		assertFalse(result.getFilteredAttributes().isEmpty());
		assertEquals(attrs.get(profileAttribute("profile")), result.getFilteredAttributes().get(profileAttribute("profile")));
	}

	@Test
	void getTranslationValuesFiltersByProfileAndRemovesPrefix() throws Exception {
		Map<AttributeName, List<String>> userDetails = new HashMap<>();
		userDetails.put(profileAttribute("translation.de"), List.of("p1:Willkommen", "p2:Willkommen-2"));
		userDetails.put(profileAttribute("translation.fr"), List.of("p1:org:Bonjour"));

		var values = invokeGetTranslationValues(userDetails);

		assertEquals("Willkommen", values.get("translation.de"));
		assertEquals("Bonjour", values.get("translation.fr"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("attributeValueCases")
	void getAttributeValueWithoutPrefixCases(String testName, String profile, String value, String expected)
			throws Exception {
		assertEquals(expected, invokeGetAttributeValueWithoutPrefix(profile, value));
	}

	private static Stream<Arguments> attributeValueCases() {
		return Stream.of(
				Arguments.of("exact profile id stays unchanged", "p1", "p1", "p1"),
				Arguments.of("two-part value strips profile prefix", "p1", "p1:mail", "mail"),
				Arguments.of("three-part value strips profile and org prefix", "p1", "p1:org:role", "role"),
				Arguments.of("non-profile value remains unchanged", "p1", "plain", "plain")
		);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, String> invokeGetTranslationValues(Map<AttributeName, List<String>> userDetails)
			throws Exception {
		Method method = IdentitySelectionService.class
				.getDeclaredMethod("getTranslationValues", String.class, String.class, Map.class);
		method.setAccessible(true);
		return (Map<String, String>) method.invoke(null, "p1", "translation", userDetails);
	}

	private static String invokeGetAttributeValueWithoutPrefix(String profileName, String value) throws Exception {
		Method method = IdentitySelectionService.class
				.getDeclaredMethod("getAttributeValueWithoutPrefix", String.class, String.class);
		method.setAccessible(true);
		return (String) method.invoke(null, profileName, value);
	}

	private static ProfileSelectionProperties profileSelectionProperties(String mode) {
		var profileSelection = mock(ProfileSelectionProperties.class);
		doReturn("profile").when(profileSelection).getProfileSelector();
		doReturn(mode).when(profileSelection).getProfileSelectionMode();
		doReturn(true).when(profileSelection).isProfileSelectionEnabled();
		return profileSelection;
	}

	private static RelyingPartyConfig relyingParty() {
		var rp = mock(RelyingPartyConfig.class);
		doReturn("rp-a").when(rp).getId();
		return rp;
	}

	private static SessionState sessionState(String id) {
		var sessionState = mock(SessionState.class);
		doReturn(id).when(sessionState).getId();
		return sessionState;
	}

	private static CpResponseData cpResponse(Map<AttributeName, List<String>> userDetails) {
		var cpResponseData = mock(CpResponseData.class);
		doReturn("cp-a").when(cpResponseData).getIssuerId();
		doReturn("name-id").when(cpResponseData).getNameId();
		doReturn(userDetails).when(cpResponseData).getUserDetailMap();
		return cpResponseData;
	}

	private static Map<AttributeName, List<String>> multiProfileAttributes() {
		Map<AttributeName, List<String>> map = new HashMap<>();
		map.put(profileAttribute("profile"), List.of("p1", "p2"));
		map.put(profileAttribute("mail"), List.of("p1:mail1@example.org", "p2:mail2@example.org"));
		return map;
	}

	private static AttributeName profileAttribute(String name) {
		return AttributeProperties.builder().name(name).build();
	}

	private static class TestIdentitySelectionService extends IdentitySelectionService {

		TestIdentitySelectionService(ApiSupport apiSupport) {
			super(apiSupport);
		}

		@Override
		protected String getSource() {
			return "LDAP";
		}
	}
}

