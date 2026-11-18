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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;
import swiss.trustbroker.common.util.WebUtil;

class AcUrlTest {

	private static final String INVALID_URL = "https?://localhost(|:443|:80)(|/test/.*)";

	private static final String VALID_URL = "https://localhost/test";

	private static final URI VALID_URI = WebUtil.getValidatedUri(VALID_URL);

	@ParameterizedTest
	@MethodSource
	void ofFormat(String url, AcceptedUrlFormat format, AcceptedUrlFormat expectedFormat, URI expectedUri,
			String expectedPattern) {
		var acUrl = AcUrl.ofFormat(url, format);
		assertEquals(url, acUrl.getUrl());
		assertEquals(expectedFormat, acUrl.getFormat());
		assertEquals(expectedUri, acUrl.getUri());
		if (expectedPattern == null) {
			assertNull(acUrl.getPattern());
		}
		else {
			assertNotNull(acUrl.getPattern());
			assertEquals(expectedPattern, acUrl.getPattern().pattern());
		}
	}

	static Object[][] ofFormat() {
		return new Object[][] {
				{ VALID_URL, AcceptedUrlFormat.FULL, AcceptedUrlFormat.FULL, VALID_URI, null },
				{ VALID_URL, null, null, VALID_URI, null },
				{ VALID_URL, AcceptedUrlFormat.ANY, AcceptedUrlFormat.ANY, VALID_URI, null },
				{ INVALID_URL, null, AcceptedUrlFormat.REGEX, null, INVALID_URL },
				{ INVALID_URL, AcceptedUrlFormat.REGEX, AcceptedUrlFormat.REGEX, null, INVALID_URL },
		};
	}

	@Test
	void asCollection() {
		var expectedAcUrl = AcUrl.builder().url(VALID_URL).uri(VALID_URI).format(AcceptedUrlFormat.FULL).build();
		assertThat(AcUrl.of(VALID_URL), is(expectedAcUrl));
		assertThat(AcUrl.asAcUrlList(Set.of(VALID_URL)), is(List.of(expectedAcUrl)));
		assertThat(AcUrl.asAcceptedUrlSet(List.of(VALID_URL)), is(Set.of(expectedAcUrl)));
	}

	@ParameterizedTest
	@MethodSource
	void derivePattern(AcUrl acUrl, String expectedPattern, int expectedErrors) {
		var errors = new ArrayList<String>();
		acUrl.derivePattern(Optional.of(errors::add));

		if (expectedPattern == null) {
			assertNull(acUrl.getPattern());
		}
		else {
			assertNotNull(acUrl.getPattern());
			assertEquals(expectedPattern, acUrl.getPattern().pattern());
		}
		assertThat(errors, hasSize(expectedErrors));
	}

	static Object[][] derivePattern() {
		return new Object[][] {
				{ AcUrl.builder().format(AcceptedUrlFormat.REGEX).url(INVALID_URL).build(), INVALID_URL, 0 },
				{ AcUrl.builder().format(AcceptedUrlFormat.REGEX).url(null).build(), null, 0 },
				{ AcUrl.builder().format(AcceptedUrlFormat.PATH_REGEX).uri(URI.create("https://localhost/path/.*")).build(), "/path/.*", 0 },
				{ AcUrl.builder().format(AcceptedUrlFormat.PATH_REGEX).uri(null).build(), null, 0 },
				{ AcUrl.builder().format(AcceptedUrlFormat.FULL).url(VALID_URL).build(), null, 0 },
				{ AcUrl.builder().format(null).url(VALID_URL).build(), null, 0 },
				{ AcUrl.builder().format(AcceptedUrlFormat.REGEX).url("(|invalidregex").build(), null, 1 }
		};
	}

}
