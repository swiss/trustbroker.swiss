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

package swiss.trustbroker.sso.dto;

import java.util.Collections;
import java.util.List;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.tuple.Pair;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.federation.xmlconfig.SloResponse;

/**
 * Combines static configuration from SloUrl with dynamic SLO notification information
 */
@Data
@RequiredArgsConstructor
public class SloNotification {

	private final SloResponse slo;

	private String url;

	private List<Pair<String, String>> queryParameters;

	private String samlLogoutRequest;

	private String samlRelayState;

	private String samlRedirectSignature;

	private String samlRedirectSignatureAlgorithm;

	private String samlHttpMethod;

	public String getEncodedSloUrl() {
		return WebUtil.htmlEncodeValue(slo.getUrl());
	}

	public String getEncodedUrl() {
		return WebUtil.htmlEncodeValue(url);
	}

	public String getDoubleEncodedUrl() {
		return WebUtil.doubleHtmlEncodeValue(url);
	}

	public List<Pair<String, String>> getDoubleEncodedQueryParameters() {
		if (queryParameters == null) {
			return Collections.emptyList();
		}
		return queryParameters.stream()
				.map(p -> Pair.of(WebUtil.doubleHtmlEncodeValue(p.getLeft()), WebUtil.doubleHtmlEncodeValue(p.getRight())))
				.toList();
	}

}
