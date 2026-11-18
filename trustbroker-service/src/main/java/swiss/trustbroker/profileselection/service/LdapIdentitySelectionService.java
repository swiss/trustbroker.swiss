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

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import swiss.trustbroker.util.ApiSupport;

/**
 * LDAP Identity Selection
 *
 * @see swiss.trustbroker.api.profileselection.service.ProfileSelectionService
 */
@Service("ldap")
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.ldap.enabled")
@ConditionalOnBooleanProperty("trustbroker.config.profileselection.enabled")
public class LdapIdentitySelectionService extends IdentitySelectionService {

	public LdapIdentitySelectionService(ApiSupport apiSupport) {
		super(apiSupport);
	}

	@Override
	protected String getSource() {
		return ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, ExternalStores.LDAP.name());
	}
}
