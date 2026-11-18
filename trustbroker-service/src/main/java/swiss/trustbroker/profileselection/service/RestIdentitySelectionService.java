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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.profileselection.dto.Profile;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import swiss.trustbroker.util.ApiSupport;

/**
 * REST Identity Selection
 *
 * @see swiss.trustbroker.api.profileselection.service.ProfileSelectionService
 */
@Service("rest")
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.rest.enabled")
@ConditionalOnBooleanProperty("trustbroker.config.profileselection.enabled")
public class RestIdentitySelectionService extends IdentitySelectionService {

	public RestIdentitySelectionService(ApiSupport apiSupport) {
		super(apiSupport);
	}

	@Override
	protected String getSource() {
		return ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, ExternalStores.REST.name());
	}

	@Override
	protected String encodeSelectedProfileId(String selectedProfileId, List<String> userProfileIds) {
		if (selectedProfileId == null || userProfileIds == null || !userProfileIds.contains(selectedProfileId)) {
			return selectedProfileId;
		}
		return encodeFrontendProfileId(selectedProfileId);
	}

	@Override
	protected String encodeProfileId(String profileId) {
		return encodeFrontendProfileId(profileId);
	}

	@Override
	protected String decodeProfileId(String profileId) {
		return decodeFrontendProfileId(profileId);
	}

	@Override
	protected Profile buildProfile(String profileValue, String name, Map<String, List<String>> additionalInformation,
										  Map<String, Map<String, String>> translationInformation) {
		return Profile.builder()
					  .id(encodeFrontendProfileId(profileValue))
					  .name(name)
					  .displayClaims(new java.util.LinkedHashMap<>(additionalInformation))
					  .translations(translationInformation)
					  .build();
	}

	private static String encodeFrontendProfileId(String profileId) {
		if (profileId == null) {
			return null;
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(profileId.getBytes(StandardCharsets.UTF_8));
	}

	private static String decodeFrontendProfileId(String profileId) {
		if (profileId == null) {
			return null;
		}
		try {
			return new String(Base64.getUrlDecoder().decode(profileId), StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException ex) {
			log.debug("SelectedProfileId is not base64 encoded, use raw value");
			return profileId;
		}
	}
}

