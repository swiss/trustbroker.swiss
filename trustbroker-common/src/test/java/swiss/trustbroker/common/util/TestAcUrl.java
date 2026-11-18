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

package swiss.trustbroker.common.util;

import java.io.Serializable;
import java.net.URI;
import java.util.regex.Pattern;

import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;

/**
 * Implementation of <code>AcceptedUrl</code> for test classes in common where <code>AcUrl</code> is not available.
 */
public record TestAcUrl(String url, URI uri, Pattern pattern, AcceptedUrlFormat format) implements AcceptedUrl, Serializable {

	public static AcceptedUrl of(String url, AcceptedUrlFormat format) {
		format = format != null ? format : AcceptedUrlFormat.FULL;
		var uri = WebUtil.getValidatedUri(url);
		var pattern = format == AcceptedUrlFormat.REGEX ? Pattern.compile(url) : null;
		return new TestAcUrl(url, uri, pattern, format);
	}

	@Override
	public String getUrl() {
		return url;
	}

	@Override
	public URI getUri() {
		return uri;
	}

	@Override
	public Pattern getPattern() { return pattern; }

	@Override
	public AcceptedUrlFormat getFormat() {
		return format;
	}
}
