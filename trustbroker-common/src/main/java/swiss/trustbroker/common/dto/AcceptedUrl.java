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

package swiss.trustbroker.common.dto;

import java.io.Serializable;
import java.net.URI;
import java.util.regex.Pattern;

/**
 * URL whitelist entry.
 * <br/>
 * Used for access control URLs or origin/referer matching. Interface is used in common, an implementation is in the XML model.
 */
public interface AcceptedUrl extends Serializable {

	/**
	 * @return URL from the config.
	 */
	String getUrl();

	/**
	 * @return URL as URI or null if not a valid URI (e.g. regular expression).
	 */
	URI getUri();

	/**
	 * @return Pattern if this type is a regular expression.
	 */
	Pattern getPattern();

	/**
	 * @return format of URL.
	 */
	AcceptedUrlFormat getFormat();
}
