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

package swiss.trustbroker.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.config.TrustBrokerProperties;

class TxnSupportTest {

	private static final String RP_TXN_ID_PARAMETER = "rp_txn_id";

	private static final String RP_TXN_ID_VALUE = "txn-12345";

	@ParameterizedTest
	@NullAndEmptySource
	void getRpTxnIdFromRequestReturnsNullIfTrackingIsDisabled(String rpTxnIdParameter) {
		var request = new MockHttpServletRequest();
		request.setParameter(RP_TXN_ID_PARAMETER, RP_TXN_ID_VALUE);
		var result = TxnSupport.getRpTxnIdFromRequest(request, givenProperties(rpTxnIdParameter));
		assertThat(result, is(nullValue()));
	}

	@Test
	void getRpTxnIdFromRequestReturnsNullIfConfiguredParameterIsMissing() {
		var request = new MockHttpServletRequest();
		var result = TxnSupport.getRpTxnIdFromRequest(request, givenProperties(RP_TXN_ID_PARAMETER));
		assertThat(result, is(nullValue()));
	}

	@Test
	void getRpTxnIdFromRequestReturnsConfiguredRequestParameter() {
		var request = new MockHttpServletRequest();
		request.setParameter(RP_TXN_ID_PARAMETER, RP_TXN_ID_VALUE);
		var result = TxnSupport.getRpTxnIdFromRequest(request, givenProperties(RP_TXN_ID_PARAMETER));
		assertThat(result, is(RP_TXN_ID_VALUE));
	}

	private static TrustBrokerProperties givenProperties(String rpTxnIdParameter) {
		var properties = new TrustBrokerProperties();
		properties.setRpTxnIdParameter(rpTxnIdParameter);
		return properties;
	}

}
