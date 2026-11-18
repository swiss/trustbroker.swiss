/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.profileselection.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionProperties;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.api.sessioncache.dto.SessionState;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import swiss.trustbroker.util.ApiSupport;

/**
 * Tests for REST Identity Selection Service
 *
 * This class extends the abstract IdentitySelectionService base class.
 * Tests verify the concrete REST implementation with Base64 encoding/decoding
 * as well as inherited common profile selection logic.
 *
 * @see IdentitySelectionService
 */
class RestIdentitySelectionServiceTest {

	private static final String PROFILE_SELECTOR = "groups";
	private static final String PROFILE_DISPLAY_NAME = "label";
	private static final String PROFILE_VALUE_CLAIM = "code";
	private static final String DEVELOPER_PROFILE = "developer";
	private static final String TESTER_PROFILE = "tester";
	private static final String SESSION_ID = "state-123";

	private final RestIdentitySelectionService restIdentitySelectionService = new RestIdentitySelectionService(mock(ApiSupport.class));

	@Test
	void buildProfileResponseEncodesRawProfileId() {
		var profileSelectionData = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties())
				.selectedProfileId(SESSION_ID)
				.applicationName("sample-app")
				.build();

		var result = restIdentitySelectionService.buildProfileResponse(profileSelectionData, cpResponseData(List.of(DEVELOPER_PROFILE)));

		assertEquals(SESSION_ID, result.getId());
		assertEquals(encoded(DEVELOPER_PROFILE), result.getProfiles().getFirst().getId());
	}

	@Test
	void validSelectedProfileAcceptsEncodedFrontendId() {
		var cpResponseData = cpResponseData(List.of(DEVELOPER_PROFILE));
		var validSelection = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties())
				.selectedProfileId(encoded(DEVELOPER_PROFILE))
				.build();
		var rawSelection = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties())
				.selectedProfileId(DEVELOPER_PROFILE)
				.build();
		var invalidSelection = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties())
				.selectedProfileId(encoded(TESTER_PROFILE))
				.build();

		assertTrue(restIdentitySelectionService.isValidSelectedProfile(validSelection, cpResponseData));
		assertTrue(restIdentitySelectionService.isValidSelectedProfile(rawSelection, cpResponseData));
		assertFalse(restIdentitySelectionService.isValidSelectedProfile(invalidSelection, cpResponseData));
	}

	@Test
	void doFinalProfileSelectionDecodesEncodedFrontendSelection() {
		var profileSelectionData = ProfileSelectionData.builder()
				.profileSelectionProperties(profileSelectionProperties())
				.selectedProfileId(encoded(DEVELOPER_PROFILE))
				.enforceSingleProfile(true)
				.build();
		var relyingPartyConfig = mock(RelyingPartyConfig.class);
		when(relyingPartyConfig.getId()).thenReturn("rp");
		var sessionState = mock(SessionState.class);
		when(sessionState.getId()).thenReturn("sid");
		var cpResponseData = cpResponseData(List.of(DEVELOPER_PROFILE, TESTER_PROFILE));

		ProfileSelectionResult result = restIdentitySelectionService.doFinalProfileSelection(
				profileSelectionData, relyingPartyConfig, cpResponseData, sessionState);

		assertEquals(DEVELOPER_PROFILE, result.getSelectedProfileId());
		assertEquals(List.of(DEVELOPER_PROFILE), result.getFilteredAttributes().get(restProfileAttribute()));
	}

	private static ProfileSelectionProperties profileSelectionProperties() {
		var profileSelectionProperties = mock(ProfileSelectionProperties.class);
		when(profileSelectionProperties.isProfileSelectionEnabled()).thenReturn(true);
		when(profileSelectionProperties.getProfileSelectionMode()).thenReturn(ProfileSelectionMode.INTERACTIVE.name());
		when(profileSelectionProperties.getProfileSelector()).thenReturn(PROFILE_SELECTOR);
		when(profileSelectionProperties.getDisplayName()).thenReturn(PROFILE_DISPLAY_NAME);
		when(profileSelectionProperties.getDisplayClaims()).thenReturn(List.of(PROFILE_VALUE_CLAIM));
		when(profileSelectionProperties.getTranslationAttributes()).thenReturn(null);
		when(profileSelectionProperties.getOrganizationSelector()).thenReturn(null);
		return profileSelectionProperties;
	}

	private static CpResponseData cpResponseData(List<String> profiles) {
		var cpResponseData = mock(CpResponseData.class);
		Map<AttributeName, List<String>> userDetails = Map.of(restProfileAttribute(), profiles);
		when(cpResponseData.getUserDetailMap()).thenReturn(userDetails);
		when(cpResponseData.getIssuerId()).thenReturn("cp");
		when(cpResponseData.getNameId()).thenReturn("nameId");
		return cpResponseData;
	}

	private static Definition restProfileAttribute() {
		return Definition.builder()
						 .name(PROFILE_SELECTOR)
						 .source(ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, ExternalStores.REST.name()))
						 .build();
	}

	private static String encoded(String value) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
	}
}
