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

package swiss.trustbroker.oidc;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

class OidcCtxPropagatorTest {

	private static final String LOCATION = "https://example.org/redirect";

	private static final String HRD_HINT_PARAMETER = "hrd_hint";

	private static final String RP_TXN_ID_PARAMETER = "rp_txn_id";

	@ParameterizedTest
	@CsvSource(value = {
			"false,acr1,clientA,login,hrd1,openid,txn123,https://example.org/redirect?rp_txn_id=txn123",
			"true,acr1,clientA,login,hrd1,openid,txn123,https://example.org/redirect?acr_values=acr1&client_id=clientA&prompt=login&hrd_hint=hrd1&scope=openid&rp_txn_id=txn123",
			"true,null,null,null,null,openid,txn123,https://example.org/redirect?scope=openid&rp_txn_id=txn123"
	}, nullValues = "null")
	void addAuthenticationContextParamsReturnsExpectedLocation(boolean fullContext,
			String acrValues, String clientId, String prompt, String hrdHint, String scope,
			String txnId, String expectedLocation) {
		var request = new MockHttpServletRequest();
		setParameterIfPresent(request, OidcUtil.OIDC_ACR_VALUES, acrValues);
		setParameterIfPresent(request, OidcUtil.OIDC_CLIENT_ID, clientId);
		setParameterIfPresent(request, OidcUtil.OIDC_PROMPT, prompt);
		setParameterIfPresent(request, HRD_HINT_PARAMETER, hrdHint);
		setParameterIfPresent(request, OidcUtil.OIDC_SCOPE, scope);
		setParameterIfPresent(request, RP_TXN_ID_PARAMETER, txnId);

		var properties = new TrustBrokerProperties();
		properties.setHrdHintParameter(HRD_HINT_PARAMETER);
		properties.setRpTxnIdParameter(RP_TXN_ID_PARAMETER);

 		assertThat(OidcCtxPropagator.addAuthenticationContextParams(LOCATION, request, properties, fullContext),
				is(expectedLocation));
	}

	private static void setParameterIfPresent(MockHttpServletRequest request, String name, String value) {
		if (value != null) {
			request.setParameter(name, value);
		}
	}

}

