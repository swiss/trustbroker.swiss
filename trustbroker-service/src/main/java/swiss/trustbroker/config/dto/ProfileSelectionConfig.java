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

package swiss.trustbroker.config.dto;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Profile selection configuration.
 * <br>
 * Potentially breaking changes:
 * <ul>
 *     <li>With 1.10.0 value of attributes changed to Object to allow nested structures.</li>
 * </ul>
 *
 * @see swiss.trustbroker.api.profileselection.service.ProfileSelectionService
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProfileSelectionConfig {

	/**
	 * Globally enable the feature.
	 * <br/>
	 * Default: false
	 * @since 1.15.0
	 */
	private boolean enabled;

	/**
	 * Defines the default profile selection service type when no explicit type is provided.
	 * <br/>
	 * Default: default
	 * This value selects the <code>NoOpProfileSelectionService</code> which is only available if no other instances of
	 * <code>ProfileSelectionService</code> are enabled. If more than one <code>ProfileSelectionService</code> is enabled,
	 * either set this property to one of them or always set store on all <code>IdmLookup</code> .
	 * @since 1.16.0
	 */
	@Builder.Default
	private String defaultService = "default";

	/**
	 * Custom attributes that might be needed by the implementation.
 	 */
	private Map<String, Object> attributes;

}
