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

package swiss.trustbroker.homerealmdiscovery.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.service.SamlServiceTestConfiguration;
import swiss.trustbroker.test.saml.util.SamlHttpTestBase;

@SpringBootTest
@ContextConfiguration(classes = { SamlServiceTestConfiguration.class, RedirectOutputService.class })
class RedirectOutputServiceTest {

	private static final String ORIGIN = "https://trustbroker.swiss";

	private static final String CROSS_ORIGIN = "https://localhost:443/path";

	private static final String CROSS_ORIGIN_HTML_ENCODED = "https&#x3a;&#x2f;&#x2f;localhost&#x3a;443&#x2f;path";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@Autowired
	private VelocityEngine velocityEngine;

	@Autowired
	private RedirectOutputService redirectOutputService;

	@ParameterizedTest
	@MethodSource
	void handleRedirectCrossOrigin(String url, String action, List<Pair<String, String>> additionalFields) throws Exception {
		mockProperties();
		var request = new MockHttpServletRequest();
		request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_MODE, WebUtil.SEC_FETCH_MODE_CORS);
		var response = new MockHttpServletResponse();

		var result = redirectOutputService.handleRedirect(request, response, url);

		assertThat(result, is(nullValue()));
		var content = response.getContentAsString();
		assertThat(content, containsString(" action=\"" + action + '"'));
		assertThat(content, is(not("")));
		for (var additionalField : additionalFields) {
			var value = SamlHttpTestBase.extractHtmlFormValue(content, additionalField.getKey());
			assertThat(value, is(additionalField.getValue()));
		}
	}

	static Object[][] handleRedirectCrossOrigin() {
		return new Object[][] {
				{ CROSS_ORIGIN, CROSS_ORIGIN_HTML_ENCODED, Collections.emptyList() },
				// URL with query parameters to be HTML encoded:
				{ CROSS_ORIGIN + "?key1=value1&key2=%22value+2%22", CROSS_ORIGIN_HTML_ENCODED,
						List.of(Pair.of("key1", "value1"), Pair.of("key2", "&quot;value&#x20;2&quot;")) },
		};
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,true",
			"://,null,true", // invalid
			"/api/v1/test,null,false", // relative
			CROSS_ORIGIN + "/api/v1/test,navigate,false", // cross-origin, fetch mode navigate
			CROSS_ORIGIN + "/api/v1/test,null,false", // cross-origin, no fetch mode
			ORIGIN + "/api/v1/test,cors,false", // same origin, absolute, fetch mode cors
			ORIGIN + "/api/v1/test?key1=value1&key2=value2,cors,false" // same origin, absolute, fetch mode cors, with query
	}, nullValues = "null")
	void handleRedirectDirectly(String url, String secFetchMode, boolean expectNull) throws Exception {
		mockProperties();
		var request = new MockHttpServletRequest();
		if (secFetchMode != null) {
			request.addHeader(WebUtil.HTTP_HEADER_SEC_FETCH_MODE, secFetchMode);
		}
		var response = new MockHttpServletResponse();
		var expected = expectNull ? null : url;

		var result = redirectOutputService.handleRedirect(request, response, url);

		assertThat(result, is(expected));
		var content = response.getContentAsString();
		assertThat(content, is(""));
	}

	private void mockProperties() {
		when(trustBrokerProperties.getPerimeterUrl()).thenReturn(ORIGIN + "/api/v1/entry");
	}
}
