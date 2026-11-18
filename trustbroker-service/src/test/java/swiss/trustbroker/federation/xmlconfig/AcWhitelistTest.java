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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.BiPredicate;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;

class AcWhitelistTest {

	@ParameterizedTest
	@MethodSource
	void calculateDerivedUrls(List<AcUrl> acUrls, List<AcceptedUrl> expectedAcUrls, int expectedErrors,
			List<String> expectedOrigins, List<AcceptedUrl> expectedRedirectUrls) {
		var acWhitelist = new AcWhitelist(acUrls);
		var errors = new ArrayList<String>();
		acWhitelist.calculateDerivedUrls(Optional.of(errors::add));
		assertThat(acWhitelist.getAcUrls(), is(expectedAcUrls));
		assertThat(errors, hasSize(expectedErrors));
		assertThat(acWhitelist.getOrigins(), is(expectedOrigins));
		assertThat(acWhitelist.getRedirectUrls(), is(expectedRedirectUrls));
	}

	static Object[][] calculateDerivedUrls() {
		return new Object[][] {
				{
					null, Collections.emptyList(), 0, Collections.emptyList(), Collections.emptyList()
				},
				{
					List.of(AcUrl.builder().url("null").build(),
							AcUrl.builder().url("/relative").build(),
							AcUrl.builder().url("https://example.trustbroker.swiss/path").build(),
							AcUrl.builder().url("custom://app/command").build(),
							AcUrl.builder().url("https://any.*.example.trustbroker.swiss/path").format(AcceptedUrlFormat.REGEX).build(),
							AcUrl.builder().url("https://sub.example.trustbroker.swiss/path/.*").format(AcceptedUrlFormat.PATH_REGEX).build(),
							AcUrl.builder().url("https://localhost/[invalid").format(AcceptedUrlFormat.REGEX).build(),
							AcUrl.builder().url("https://test.example.trustbroker.swiss/#fragment").build()),
					List.of(AcUrl.ofFormat("null", AcceptedUrlFormat.IGNORED),
							AcUrl.ofFormat("/relative", AcceptedUrlFormat.IGNORED),
							AcUrl.ofFormat("https://example.trustbroker.swiss/path", null),
							AcUrl.ofFormat("custom://app/command", null),
							AcUrl.ofFormat("https://any.*.example.trustbroker.swiss/path", AcceptedUrlFormat.REGEX),
							AcUrl.ofFormat("https://sub.example.trustbroker.swiss/path/.*", AcceptedUrlFormat.PATH_REGEX),
							AcUrl.ofFormat("https://localhost/[invalid", AcceptedUrlFormat.IGNORED),
							AcUrl.ofFormat("https://test.example.trustbroker.swiss/#fragment", null)),
					3, // number of IGNORED
					List.of("https://example.trustbroker.swiss", "custom://app", "https://sub.example.trustbroker.swiss",
							"https://test.example.trustbroker.swiss"),
					List.of(AcUrl.ofFormat("https://example.trustbroker.swiss/path", null),
							AcUrl.ofFormat("custom://app/command", null),
							AcUrl.ofFormat("https://any.*.example.trustbroker.swiss/path", AcceptedUrlFormat.REGEX),
							AcUrl.ofFormat("https://sub.example.trustbroker.swiss/path/.*", AcceptedUrlFormat.PATH_REGEX))
				}
		};
	}

	@ParameterizedTest
	@MethodSource
	void getDefault(List<AcUrl> acUrls, Boolean useDefault, Optional<String> expectedResult) {
		var acWhitelist = new AcWhitelist(acUrls);
		acWhitelist.setUseDefault(useDefault);
		assertThat(acWhitelist.getDefault(), is(expectedResult));
	}

	static Object[][] getDefault() {
		return new Object[][] {
				{ null, Boolean.TRUE, Optional.empty() },
				{ Collections.emptyList(), Boolean.TRUE, Optional.empty() },
				{ List.of(AcUrl.of("ignored")), null, Optional.empty() },
				{ List.of(AcUrl.of("ignored")), Boolean.FALSE, Optional.empty() },
				{ List.of(AcUrl.of("defaultAcs"), AcUrl.of("ignored")), Boolean.TRUE, Optional.of("defaultAcs") }
		};
	}


	@ParameterizedTest
	@MethodSource
	void findFirst(List<AcUrl> acUrls, String checkUrl,
			BiPredicate<String, String> matcher, Optional<String> expectedResult) {
		var acWhitelist = new AcWhitelist(acUrls);
		assertThat(acWhitelist.findFirst(matcher, checkUrl), is(expectedResult));
	}

	static Object[][] findFirst() {
		BiPredicate<String, String> contains = String::contains;
		BiPredicate<String, String> equals = String::equals;
		BiPredicate<String, String> startsWith = String::startsWith;
		var baseUrl = "https://example.trustbroker.swiss";
		var acUrl = baseUrl + "/path";
		var acUrlExtended = acUrl + "/ext";
		var acUrls = List.of(AcUrl.of("mismatch"), AcUrl.of(acUrl), AcUrl.of(acUrlExtended));
		return new Object[][] {
				{ null, "test", contains, Optional.empty() },
				{ Collections.emptyList(), "test", startsWith,  Optional.empty() },
				{
						acUrls,
						baseUrl,
						startsWith,
						Optional.of(acUrl)
				},
				{
						acUrls,
						acUrlExtended,
						equals,
						Optional.of(acUrlExtended)
				},
				{
						acUrls,
						"path",
						contains,
						Optional.of(acUrl)
				},
				{
						acUrls,
						"path",
						startsWith,
						Optional.empty()
				},
		};
	}
}
