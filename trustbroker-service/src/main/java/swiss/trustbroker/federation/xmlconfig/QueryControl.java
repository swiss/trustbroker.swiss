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

package swiss.trustbroker.federation.xmlconfig;

import org.apache.commons.lang3.EnumUtils;

/**
 * Control of an IDM query in a lookup chain.
 *
 * @since 1.16.0
 */
public enum QueryControl {
	/**
	 * Query is responsible for primary user lookup.
	 */
	PRIMARY,
	/**
	 * Query enriches an already identified user.
	 */
	ADDITIONAL;

	public static QueryControl of(String name) {
		return EnumUtils.getEnum(QueryControl.class, name);
	}
}


