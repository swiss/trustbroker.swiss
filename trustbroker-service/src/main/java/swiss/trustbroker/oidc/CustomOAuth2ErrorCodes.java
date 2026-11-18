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

package swiss.trustbroker.oidc;

/**
 * Shared OAuth2 error descriptions and reference URI used by custom OIDC endpoints.
 */
public final class CustomOAuth2ErrorCodes {

	public static final String ACCESS_TOKEN_REQUEST_ERROR_URI =
			"https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	public static final String ERROR_MSG_UNAUTHORIZED_CLIENT = "unauthorized client";

	public static final String ERROR_MSG_INVALID_REQUEST = "invalid request";

	public static final String ERROR_MSG_INVALID_GRANT = "invalid grant";

	public static final String ERROR_MSG_INVALID_TOKEN = "invalid token";

	public static final String ERROR_MSG_INVALID_AUDIENCE = "invalid audience";

	public static final String ERROR_MSG_INVALID_RESOURCE = "invalid resource";

	public static final String ERROR_MSG_ACCESS_DENIED = "access denied";

	public static final String ERROR_MSG_SERVER_ERROR = "server error";

	private CustomOAuth2ErrorCodes() {
	}
}

