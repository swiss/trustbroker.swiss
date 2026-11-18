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

package swiss.trustbroker.sessioncache.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.saml.dto.CpResponse;

class StateDataTest {

	@Test
	void addAuthnRequest() {
		var stateData = StateData.builder().id("id").build();
		stateData.addCompletedAuthnRequest("req1");
		stateData.addCompletedAuthnRequest("req2");
		assertThat(stateData.getCompletedAuthnRequests(), is(List.of("req1", "req2")));
	}

	@Test
	void init() {
		var stateData = StateData.builder().id("id").build();
		assertThat(stateData.isValid(), is(true));
		assertThat(stateData.getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
	}

	@Test
	void reInit() {
		var spStateData = StateData.builder().id("spId").build();
		var stateData = StateData.builder().id("id").spStateData(spStateData).build();
		stateData.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
		spStateData.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);

		// precondition
		assertThat(stateData.isExpired(), is(true));

		stateData.reInit();

		// postcondition
		assertThat(stateData.isExpired(), is(false));
		assertThat(stateData.getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
		assertThat(spStateData.getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
	}

	@Test
	void initSsoState() {
		var stateData = StateData.builder().id("id").build();
		assertThat(stateData.hasSsoState(), is(false));
		assertThat(stateData.getSsoState(), is(nullValue()));
		var ssoState = stateData.initializedSsoState();
		assertThat(stateData.hasSsoState(), is(true));
		assertThat(stateData.getSsoState(), is(ssoState));
	}

	@Test
	void addSsoParticipant() {
		var stateData = StateData.builder().id("id").build();
		assertTrue(stateData.addSsoParticipant(new SsoSessionParticipant("rpIssuer1", "cpIssuer1", "acs1", null, null)));
		assertTrue(stateData.addSsoParticipant(new SsoSessionParticipant("rpIssuer1", "cpIssuer2", "acs1", null, null)));
		// duplicate:
		assertFalse(stateData.addSsoParticipant(new SsoSessionParticipant("rpIssuer1", "cpIssuer2", "acs1", null, null)));
		assertTrue(stateData.addSsoParticipant(new SsoSessionParticipant("rpIssuer2", "cpIssuer2", "acs2", null, null)));
		assertThat(stateData.hasSsoState(), is(true));
		assertThat(stateData.getSsoState(), is(not(nullValue())));
		var result = stateData.getSsoState().getSsoParticipants();
		assertThat(result, containsInAnyOrder(
				new SsoSessionParticipant("rpIssuer1", "cpIssuer1", "acs1", null, null),
				new SsoSessionParticipant("rpIssuer1", "cpIssuer2", "acs1", null, null),
				new SsoSessionParticipant("rpIssuer2", "cpIssuer2", "acs2", null, null)));
	}

	@ParameterizedTest
	@MethodSource("setOidcScopesCases")
	void setOidcScopes(String testName, Map<String, String> rpContext, String expectedScopes, List<String> expectedParsedScopes) {
		var sourceState = StateData.builder().id("id").rpContext(rpContext).build();
		var cpResponse = new CpResponse();

		var result = StateData.setOidcScopes(cpResponse, sourceState);

		assertThat(result, is(expectedScopes));
		if (expectedParsedScopes == null) {
			assertThat(cpResponse.getOidcScopes(), is(nullValue()));
		}
		else {
			assertThat(cpResponse.getOidcScopes(), contains(expectedParsedScopes.toArray(new String[0])));
		}
	}

	static Object[][] setOidcScopesCases() {
		return new Object[][] {
				{ "null rpContext", null, null, null },
				{ "missing scope entry", Map.of("client_id", "test-client"), null, null },
				{ "blank scope value", Map.of(OidcUtil.OIDC_SCOPE, "   "), "   ", null },
				{
						"split dedupe preserve order",
						Map.of(OidcUtil.OIDC_SCOPE, "openid profile email openid profile"),
						"openid profile email openid profile",
						List.of("openid", "profile", "email")
				}
		};
	}
}
