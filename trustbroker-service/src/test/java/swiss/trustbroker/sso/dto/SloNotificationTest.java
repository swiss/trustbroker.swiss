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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import swiss.trustbroker.federation.xmlconfig.SloResponse;

class SloNotificationTest {

	private static final String LOGOUT_URL = "https://example.trustbroker.swiss/logout?a=b&c=\"d\"";

	private static final String ENCODED_LOGOUT_URL = "https&#x3a;&#x2f;&#x2f;example.trustbroker.swiss"
			+ "&#x2f;logout"
			+ "&#x3f;a&#x3d;b"
			+ "&amp;c&#x3d;&quot;d&quot;";

	private static final String DOUBLE_ENCODED_LOGOUT_URL =
			"https&amp;&#x23;x3a&#x3b;&amp;&#x23;x2f&#x3b;&amp;&#x23;x2f&#x3b;example.trustbroker.swiss"
					+ "&amp;&#x23;x2f&#x3b;logout"
					+ "&amp;&#x23;x3f&#x3b;a&amp;&#x23;x3d&#x3b;b"
					+ "&amp;amp&#x3b;c&amp;&#x23;x3d&#x3b;&amp;quot&#x3b;d&amp;quot&#x3b;";

	@Test
	void testGetEncodedUrlWithNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.setUrl(null);

		assertThat(notification.getEncodedUrl(), is(nullValue()));
		assertThat(notification.getEncodedSloUrl(), is(nullValue()));
	}

	@Test
	void testGetEncodedUrlWithNonNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.setUrl(LOGOUT_URL);

		assertThat(notification.getEncodedUrl(), is(ENCODED_LOGOUT_URL));
	}

	@Test
	void testGetSloEncodedUrlWithNonNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.getSlo().setUrl(LOGOUT_URL);

		assertThat(notification.getEncodedSloUrl(), is(ENCODED_LOGOUT_URL));
	}

	@Test
	void testGetDoubleEncodedUrlWithNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.setUrl(null);

		assertThat(notification.getDoubleEncodedUrl(), is(nullValue()));
	}

	@Test
	void testGetDoubleEncodedUrlWithNonNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.setUrl(LOGOUT_URL);

		assertThat(notification.getDoubleEncodedUrl(), is(DOUBLE_ENCODED_LOGOUT_URL));
	}

	@Test
	void testGetDoubleEncodedQueryParametersWithNullValue() {
		var notification = new SloNotification(new SloResponse());

		notification.setQueryParameters(null);

		assertThat(notification.getDoubleEncodedQueryParameters(), is(empty()));
	}

	@Test
	void testGetDoubleEncodedQueryParametersWithNonNullValue() {
		var notification = new SloNotification(new SloResponse());
		notification.setQueryParameters(List.of(
				Pair.of("q\"", "x\"y"),
				Pair.of("a&b", "c&d"),
				Pair.of("foo", "bar")
		));

		assertThat(notification.getDoubleEncodedQueryParameters(), is(List.of(
				Pair.of("q&amp;quot&#x3b;", "x&amp;quot&#x3b;y"),
				Pair.of("a&amp;amp&#x3b;b", "c&amp;amp&#x3b;d"),
				Pair.of("foo", "bar")
		)));
	}

}

