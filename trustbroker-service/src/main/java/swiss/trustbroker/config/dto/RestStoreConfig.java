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

import java.util.LinkedHashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration for REST (SCIM) store sub-system.
 * @since 1.16.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RestStoreConfig {

	/**
	 * Enables the REST store sub-system.
	 * <br/>
	 * Default: false
	 */
	private boolean enabled;

	/**
	 * Named endpoints (max 3), matched against IDMQuery.name.
	 * Each entry carries its own baseUrl, authentication, truststore and network (connect/response timeouts).
	 */
	private Map<String, RestServiceEndpointConfig> stores = new LinkedHashMap<>();

	/**
	 * Placeholder fallback value when an input attribute is not available.
	 * <br/>
	 * Default: UNDEF
	 */
	private String undefined = "UNDEF";
}
