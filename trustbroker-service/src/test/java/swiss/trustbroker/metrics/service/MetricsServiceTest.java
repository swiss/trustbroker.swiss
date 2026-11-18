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

package swiss.trustbroker.metrics.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.audit.dto.EventType;

class MetricsServiceTest {

	@ParameterizedTest
	@MethodSource
	void computeNamePrefixTest(EventType eventType, String expectedPrefix) {
		assertEquals(expectedPrefix, MetricsService.computeNamePrefix(eventType));
	}

	static Stream<Arguments> computeNamePrefixTest() {
		return Stream.of(
				// SAML events → "saml."
				Arguments.of(EventType.AUTHN_REQUEST, MetricsService.SAML_LABEL),
				Arguments.of(EventType.RESPONSE, MetricsService.SAML_LABEL),
				Arguments.of(EventType.LOGOUT_REQUEST, MetricsService.SAML_LABEL),
				Arguments.of(EventType.LOGOUT_RESPONSE, MetricsService.SAML_LABEL),
				// OIDC events → "oidc."
				Arguments.of(EventType.OIDC_TOKEN_REQUEST, MetricsService.OIDC_LABEL),
				Arguments.of(EventType.OIDC_TOKEN, MetricsService.OIDC_LABEL),
				Arguments.of(EventType.OIDC_IDTOKEN, MetricsService.OIDC_LABEL),
				Arguments.of(EventType.OIDC_LOGOUT, MetricsService.OIDC_LABEL),
				// WS-Trust events → "wstrust."
				Arguments.of(EventType.RST_REQUEST, MetricsService.WS_TRUST_LABEL),
				Arguments.of(EventType.RST_RESPONSE, MetricsService.WS_TRUST_LABEL),
				// Default fallback → lowercase enum name
				Arguments.of(EventType.ARTIFACT_RESOLVE, "artifact_resolve"),
				Arguments.of(EventType.ARTIFACT_RESPONSE, "artifact_response")
		);
	}
}

