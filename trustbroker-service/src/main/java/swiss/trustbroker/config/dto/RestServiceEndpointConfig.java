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

import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.common.config.KeystoreProperties;

/**
 * Configuration for a named REST endpoint.
 *
 * @since 1.16.0
 */
@Data
@NoArgsConstructor
public class RestServiceEndpointConfig {

	/**
	 * Base URL for REST requests of this endpoint.
	 * Must be a static endpoint without placeholders or query parameters.
	 */
	private String baseUrl;

	/**
	 * Authentication parameters for this endpoint.
	 */
	private AuthenticationConfig authentication = new AuthenticationConfig();

	/**
	 * Truststore for TLS verification of this endpoint.
	 */
	private KeystoreProperties truststore;

	/**
	 * Network parameters for this endpoint.
	 * <br/>
	 * The HTTP connect timeout is taken from {@link NetworkConfig#getBackendConnectTimeoutSec()} and the HTTP response
	 * timeout from {@link NetworkConfig#getBackendResponseTimeoutSec()}.
	 *
	 * @since 1.16.0
	 */
	private NetworkConfig network = new NetworkConfig();

}
