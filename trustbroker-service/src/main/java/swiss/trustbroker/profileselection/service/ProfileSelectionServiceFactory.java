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

import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;

@Component
@Slf4j
public class ProfileSelectionServiceFactory {

	private final Map<String, ProfileSelectionService> services;

	private final TrustBrokerProperties trustBrokerProperties;

	@Autowired
	public ProfileSelectionServiceFactory(Map<String, ProfileSelectionService> services,
			TrustBrokerProperties trustBrokerProperties) {
		this.services = services;
		this.trustBrokerProperties = trustBrokerProperties;
	}

	public ProfileSelectionService getProfileSelectionService(String type) {
		if (services.size() == 1) {
			return services.values().iterator().next();
		}
		if (StringUtils.isEmpty(type)) {
			type = trustBrokerProperties.getProfileSelection().getDefaultService();
			if (type == null) {
				type = "";
			}
			log.debug("Using default profile selection service of type={}", type);
		}
		var service = services.get(type.toLowerCase());
		if (service == null) {
			throw new TechnicalException(String.format("Unknown profile selection service type=%s availableTypes=%s -"
					+ "configure trustbroker.config.profileselection.defaultService or specify the store type in IdmLookup.",
					type, services.keySet()));
		}
		return service;
	}

	public ProfileSelectionService getProfileSelectionService(IdmLookup idmLookup) {
		String storeType = null;
		if (idmLookup != null) {
			// Check IDMLookup.store
			var directStore = idmLookup.getStore();
			if (ExternalStores.isValid(directStore)) {
				storeType = directStore;
			}
			else {
				// Check IDMLookup.IDMQuery[].store
				List<IdmQuery> queries = idmLookup.getQueries();
				if (queries != null) {
					storeType = queries.stream()
							.map(IdmQuery::getStore)
							.filter(ExternalStores::isValid)
							.findFirst()
							.orElse(null);
				}
			}
		}
		return getProfileSelectionService(storeType);
	}
}
