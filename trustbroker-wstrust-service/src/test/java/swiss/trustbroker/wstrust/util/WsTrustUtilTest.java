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

package swiss.trustbroker.wstrust.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.SamlInitializer;

class WsTrustUtilTest {

	@BeforeAll
	static void setupAll() {
		SamlInitializer.initSamlSubSystem();
	}

	@ParameterizedTest
	@CsvSource(value = { "testAddress,false", "testAddress,true" })
	void getAddressFromRequest(String address, boolean wsa) throws Exception {
		var request = WsTrustTestUtil.givenRst(WSTrustConstants.WSA_ACTION_RST_ISSUE, address, wsa);
		XMLObjectSupport.getMarshaller(request).marshall(request); // needs DOM
		assertThat(WsTrustUtil.getAddressFromRequest(request), is(address));
	}

	@Test
	void missingAddressFromRequest() throws Exception {
		var request = WsTrustTestUtil.givenRst(WSTrustConstants.WSA_ACTION_RST_ISSUE, null, false);
		XMLObjectSupport.getMarshaller(request).marshall(request); // needs DOM
		assertThrows(RequestDeniedException.class, () -> WsTrustUtil.getAddressFromRequest(request));
	}

	@Test
	void getNameID() {
		var assertion = WsTrustTestUtil.givenAssertion();
		assertThat(WsTrustUtil.getNameID(assertion).getValue(), is(WsTrustTestUtil.NAME_ID));
	}

	@Test
	void getAuthnContextClasses() {
		var assertion = WsTrustTestUtil.givenAssertion();
		assertThat(WsTrustUtil.getAuthnContextClasses(assertion), is(List.of(WsTrustTestUtil.CONTEXT_CLASS)));
	}
}
