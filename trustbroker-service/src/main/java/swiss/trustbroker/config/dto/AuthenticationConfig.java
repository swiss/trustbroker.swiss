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
import swiss.trustbroker.common.config.KeystoreProperties;

/**
 * Authentication parameters towards a service.
 * @since 1.16.0
 */
@Data
public class AuthenticationConfig {

	/**
	 * Authentication method.
	 * <br/>
	 * Default: NONE
	 */
	private AuthenticationMethod method = AuthenticationMethod.NONE;

	/**
	 * Username for BASIC authentication method.
	 */
	private String username;

	/**
	 * Password for BASIC authentication method.
	 */
	private String password;

	/**
	 * Token for BEARER authentication method.
	 */
	private String bearerToken;

	/**
	 * Keystore for REST client CERTIFICATE (mTLS) authentication method.
	 */
	private KeystoreProperties keystore;
}
