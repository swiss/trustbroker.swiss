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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;

class UrlAcceptorTest {

	@ParameterizedTest
	@CsvSource(value = {
			"http://test.trustbroker.swiss,true",
			"http://test.trustbroker.swiss/path,true",
			"http://test,false",
			"http://t,false",
			"https://test.trustbroker.swiss,false",
			"https://example.trustbroker.swiss/bar/,true",
			"http://localhost,true",
			"http://user1@localhost,false",
			"https://localhost,true",
			"https://localhost:5220,true",
			"https://localhost:5220/,true",
			"http://127.0.0.1:5220,false",
			"https://127.0.0.1:5220,true",
			"https://127.0.0.1:5220/,true"
	})
	void isTrustedOriginTest(String url, boolean expected) {
		Set<AcceptedUrl> redirectUris = Set.of(
				TestAcUrl.of("http://test.trustbroker.swiss", AcceptedUrlFormat.PREFIX),  // includes http://test.trustbroker.swiss
				TestAcUrl.of("https://example.trustbroker.swiss/foo/", AcceptedUrlFormat.PREFIX),  // path ignored for origin
				TestAcUrl.of("https://localhost:0", AcceptedUrlFormat.FULL), // special matching for localhost
				TestAcUrl.of("http://localhost:?([0-9]*?)/?", AcceptedUrlFormat.REGEX) // regex match, does not consider localhost variants
		);
		assertThat(UrlAcceptor.isTrustedOrigin(url, redirectUris), is(expected));
		// backward compatibility check with format ANY:
		Set<AcceptedUrl> redirectUrisCompat = Set.of(
				TestAcUrl.of("http://test.trustbroker.swiss/.*", AcceptedUrlFormat.ANY),  // includes http://test.trustbroker.swiss
				TestAcUrl.of("https://example.trustbroker.swiss/foo/.*", AcceptedUrlFormat.ANY),  // path ignored for origin
				TestAcUrl.of("https://localhost:0", AcceptedUrlFormat.ANY), // special matching for localhost
				TestAcUrl.of("http://localhost:?([0-9]*?)/?", AcceptedUrlFormat.ANY) // regex match, does not consider localhost variants
		);
		assertThat(UrlAcceptor.isTrustedOrigin(url, redirectUrisCompat), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// invalid
			"null,null,FULL,false,false",
			"https://localhost,null,FULL,false,false",
			"null,https://localhost,FULL,false,false",
			"invalid,invalid,FULL,false,false",
			"/relative,/relative,IGNORED,false,false",
			// https port
			"https://localhost,https://localhost,FULL,false,true",
			"https://localhost:443,https://localhost,FULL,false,true",
			"https://localhost,https://localhost:443,FULL,false,true",
			"https://localhost:443,https://localhost:443,FULL,false,true",
			"https://localhost:443,https://localhost:80,FULL,false,false",
			"https://localhost:80,https://localhost:443,FULL,false,false",
			"https://localhost:80,https://localhost:0,FULL,false,true",
			// http port
			"http://localhost,http://localhost:80,FULL,false,true",
			// path
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same,FULL,false,true",
			"https://example.trustbroker.swiss/path/notsame,https://example.trustbroker.swiss/path/differs,FULL,false,false",
			"https://example.trustbroker.swiss:443/path/anything,https://example.trustbroker.swiss/path/.*,PREFIX,false,true",
			"https://example.trustbroker.swiss:443/path,https://example.trustbroker.swiss/path/.*,PREFIX,false,true",
			"https://example.trustbroker.swiss/path2/anything,https://example.trustbroker.swiss/path/.*,PREFIX,false,false",
			"https://example.trustbroker.swiss/path/this.html,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,false,true",
			"https://example.trustbroker.swiss/path/that.html,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,false,true",
			"https://example.trustbroker.swiss/path/that.php,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,false,false",
			// regexp in path
			"https://host/admin0,https://host/admin[0-9]/.*,REGEX,false,false", // regexp does not parse as URI
			"https://host/admin1/,https://host/admin./.*,PATH_REGEX,false,true",
			"https://host/admin2/x,https://host/admin./.+,PATH_REGEX,false,true",
			"https://host/admin3/some,https://host/admin./.*,PATH_REGEX,false,true",
			// origin matching (we use referrer as fallback, so test also with / or a path)
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,true,true",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,true,true",
			"https://example.trustbroker.swiss/other,https://example.trustbroker.swiss:443/path/th.*html,PATH_REGEX,true,true",
			"https://localhost:80,https://localhost:0/path,FULL,true,true",
			"https://localhost:80/,https://localhost:0/path,FULL,true,true",
			"https://localhost:80/other,https://localhost:0/path,FULL,true,true",
			// custom scheme
			"myapp://redirect,myapp://redirect,FULL,false,true"
	}, nullValues = "null")
	void testUrlOkForAccess(String check, String accept, AcceptedUrlFormat format, boolean ignorePath, boolean expected) {
		var acceptedUrl = givenAcceptedUrl(accept, format);
		assertThat(UrlAcceptor.isUrlOkForAccess(check, acceptedUrl, ignorePath), is(expected));
		if (ignorePath) {
			assertThat(
					UrlAcceptor.isUrlOkForAccessIgnoringPath(WebUtil.getValidatedUri(check), acceptedUrl.getUri()), is(expected));
		}
		else {
			assertThat(UrlAcceptor.isUrlOkForAccess(WebUtil.getValidatedUri(check), acceptedUrl), is(expected));

		}
		// backward compatibility check with format ANY:
		assertThat(UrlAcceptor.isUrlOkForAccess(check, givenAcceptedUrl(accept, AcceptedUrlFormat.ANY), ignorePath), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// localhost
			"https://localhost,https://localhost,FULL,true",
			"https://localhost,https://localhost/.*,PREFIX,true",
			"https://localhost:443,https://localhost/.*,PREFIX,true",
			"https://localhost,https://localhost:443/.*,PREFIX,true",
			"https://127.0.0.1,https://localhost:443/.*,PREFIX,true",
			"https://user@127.0.0.1,https://localhost:443/.*,PREFIX,false",
			"https://user:pw@127.0.0.1,https://localhost:443/.*,PREFIX,false",
			"https://localhost:80,https://localhost:443,FULL,false",
			"https://localhost:80,https://localhost:0,FULL,true",
			"https://localhost:80,https://localhost:.*/.*,REGEX,compat", // REGEX requires trailing /, ANY has special handling
			"https://localhost:80/,https://localhost:.*/.*,REGEX,true", // OK for REGEX
			"https://localhost:80,https://localhost:.*(.*|),REGEX,true", // REGEX allows missing trailing /
			// should not run into urlOkForAccess (URI.getPort is an int)
			// Sub-path ok by accepting /.* as nothing
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same,FULL,true",
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same/.*,PREFIX,true",
			"https://example.trustbroker.swiss/path/other,https://example.trustbroker.swiss/path/same/.*,PREFIX,false"
	}, nullValues = "null")
	void testRedirectUriOkForAccess(String check, String accept, AcceptedUrlFormat format, String expected) {
		var expectedResult = "true".equals(expected);
		assertThat(UrlAcceptor.isRedirectUrlOkForAccess(check, Set.of(givenAcceptedUrl(accept, format))), is(expectedResult));
		// backward compatibility check with format ANY:
		expectedResult |= "compat".equals(expected);
		assertThat(UrlAcceptor.isRedirectUrlOkForAccess(check, Set.of(givenAcceptedUrl(accept, AcceptedUrlFormat.ANY))), is(expectedResult));
	}

	private static AcceptedUrl givenAcceptedUrl(String accept, AcceptedUrlFormat format) {
		if (format == AcceptedUrlFormat.PREFIX) {
			accept = accept.replace(".*", "");
		}
		return TestAcUrl.of(accept, format);
	}

}
