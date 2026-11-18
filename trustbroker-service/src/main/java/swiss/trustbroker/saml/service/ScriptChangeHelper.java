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

package swiss.trustbroker.saml.service;

import java.util.Collections;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;

public class ScriptChangeHelper {

	private ScriptChangeHelper() {
		// utility class
	}

	// groovy manipulated data saving
	static void updateStateOnScriptChanges(StateCacheService stateCacheService, StateData stateData, RpRequest rpRequest,
										   boolean rememberIdpSelection) {
		if (stateData == null || stateData.getSpStateData() == null) {
			return;
		}
		var spStateData = stateData.getSpStateData();
		var changed = false;
		// QoA changes
		if (!CollectionUtils.isEqualCollection(stateData.getRpContextClasses(), rpRequest.getContextClasses())) {
			spStateData.setContextClasses(rpRequest.getContextClasses());
			changed = true;
		}
		// application disambiguation
		if (spStateData.getApplicationName() != null && !spStateData.getApplicationName().equals(rpRequest.getApplicationName())) {
			spStateData.setApplicationName(rpRequest.getApplicationName());
			changed = true;
		}
		// internal context handling
		if (!spStateData.getRpContext().equals(rpRequest.getContext())) {
			spStateData.setComparisonType(rpRequest.getComparisonType());
			spStateData.getRpContext().putAll(rpRequest.getContext());
			changed = true;
		}
		// remember IDP selection (in BeforeHrd hook only but not on BeforeCpRequest)
		if (rememberIdpSelection) {
			var selectableCpIssuerIds = calculateSelectableCpIssuerIds(rpRequest);
			var storedCpIssuerIds = spStateData.getSelectableCpIssuerIds() != null ?
					spStateData.getSelectableCpIssuerIds() : Collections.emptyList();
			if (!CollectionUtils.isEqualCollection(storedCpIssuerIds, selectableCpIssuerIds)) {
				spStateData.setSelectableCpIssuerIds(selectableCpIssuerIds);
				changed = true;
			}
		}
		// performance optimized saving
		if (changed) {
			stateCacheService.save(stateData, AssertionConsumerService.class.getSimpleName());
		}
	}

	private static List<String> calculateSelectableCpIssuerIds(RpRequest rpRequest) {
		if (CollectionUtils.isEmpty(rpRequest.getClaimsProviders())) {
			return Collections.emptyList();
		}
		return rpRequest.getClaimsProviders().stream().map(ClaimsProvider::getId).toList();
	}

}
