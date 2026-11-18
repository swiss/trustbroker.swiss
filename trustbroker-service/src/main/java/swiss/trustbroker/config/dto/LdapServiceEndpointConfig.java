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

/**
 * Configuration for a named LDAP endpoint.
 *
 * @since 1.16.0
 */
@Data
@NoArgsConstructor
public class LdapServiceEndpointConfig {

	/**
	 * LDAP URL for this endpoint (for example ldaps://ldap.example.org:636).
	 */
	private String url;

	/**
	 * Authentication parameters for this endpoint.
	 * <br/>
	 * LDAP currently supports only username/password credentials.
	 */
	private AuthenticationConfig authentication = new AuthenticationConfig();

	/**
	 * Network parameters for this endpoint.
	 * <br/>
	 * The TCP connect timeout is taken from {@link NetworkConfig#getBackendConnectTimeoutSec()} (JNDI
	 * com.sun.jndi.ldap.connect.timeout) and the response timeout from {@link NetworkConfig#getBackendResponseTimeoutSec()}
	 * (JNDI com.sun.jndi.ldap.read.timeout). Both expect milliseconds, so the values are converted when applied.
	 *
	 * @since 1.16.0
	 */
	private NetworkConfig network = new NetworkConfig();
	/**
	 * Connection pooling parameters for this endpoint.
	 * <br/>
	 * Pooling is enabled by default. Set {@code pool.enabled=false} to open a fresh connection per operation.
	 *
	 * @since 1.16.0
	 */
	private LdapPoolConfig pool = new LdapPoolConfig();

}

