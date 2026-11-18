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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ProfileSelectionConfig;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;

class ProfileSelectionServiceFactoryTest {

	@Test
	void getProfileSelectionServiceReturnsOnlyServiceWhenSingleImplementationExists() {
		var onlyService = mock(ProfileSelectionService.class);
		var factory = new ProfileSelectionServiceFactory(Map.of("any", onlyService), mock(TrustBrokerProperties.class));

		assertSame(onlyService, factory.getProfileSelectionService("ldap"));
	}

	@Test
	void getProfileSelectionServiceUsesDefaultTypeWhenTypeIsBlank() {
		var ldap = mock(ProfileSelectionService.class);
		var rest = mock(ProfileSelectionService.class);
		var properties = mock(TrustBrokerProperties.class);
		doReturn(ProfileSelectionConfig.builder().defaultService("rest").build()).when(properties).getProfileSelection();
		var factory = new ProfileSelectionServiceFactory(Map.of("ldap", ldap, "rest", rest), properties);

		assertSame(rest, factory.getProfileSelectionService(""));
	}

	@Test
	void getProfileSelectionServiceThrowsForUnknownType() {
		var ldap = mock(ProfileSelectionService.class);
		var rest = mock(ProfileSelectionService.class);
		var properties = mock(TrustBrokerProperties.class);
		doReturn(ProfileSelectionConfig.builder().defaultService("ldap").build()).when(properties).getProfileSelection();
		var factory = new ProfileSelectionServiceFactory(Map.of("ldap", ldap, "rest", rest), properties);

		assertThrows(TechnicalException.class, () -> factory.getProfileSelectionService("missing"));
	}

	@Test
	void getProfileSelectionServiceResolvesFromIdmLookupStore() {
		var ldap = mock(ProfileSelectionService.class);
		var rest = mock(ProfileSelectionService.class);
		var properties = mock(TrustBrokerProperties.class);
		doReturn(ProfileSelectionConfig.builder().defaultService("rest").build()).when(properties).getProfileSelection();
		var factory = new ProfileSelectionServiceFactory(Map.of("ldap", ldap, "rest", rest), properties);

		var idmLookup = IdmLookup.builder().store("LDAP").build();

		assertSame(ldap, factory.getProfileSelectionService(idmLookup));
	}

	@Test
	void getProfileSelectionServiceFallsBackToFirstValidQueryStore() {
		var ldap = mock(ProfileSelectionService.class);
		var rest = mock(ProfileSelectionService.class);
		var properties = mock(TrustBrokerProperties.class);
		doReturn(ProfileSelectionConfig.builder().defaultService("ldap").build()).when(properties).getProfileSelection();
		var factory = new ProfileSelectionServiceFactory(Map.of("ldap", ldap, "rest", rest), properties);

		var idmLookup = IdmLookup.builder()
				.store("INVALID")
				.queries(List.of(
						IdmQuery.builder().store("UNKNOWN").build(),
						IdmQuery.builder().store("REST").build()))
				.build();

		assertSame(rest, factory.getProfileSelectionService(idmLookup));
	}
}

