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

package swiss.trustbroker.script.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Script;
import swiss.trustbroker.federation.xmlconfig.Scripts;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.RpRequest;

/**
 * Verifies that a Groovy script configured for each supported hook type is actually invoked by the matching process method.
 */
@SpringBootTest
@ContextConfiguration(classes = ScriptService.class)
class ScriptServiceHookTest {

	private static final String SCRIPT = "scripts/hooks/RecordHookCall.groovy"; // on classpath

	private static final String ISSUER_RP = "rpIssuer1";

	private static final String ISSUER_CP = "cpIssuer1";

	private static final String REFERRER = "https://referrer.trustbroker.swiss";

	private static final String ON_REQUEST = "OnRequest";

	private static final String BEFORE_HRD = "BeforeHrd";

	private static final String BEFORE_CP_REQUEST = "BeforeCpRequest";

	private static final String ON_CP_REQUEST = "OnCpRequest";

	private static final String BEFORE_IDM = "BeforeIdm";

	private static final String AFTER_IDM = "AfterIdm";

	private static final String AFTER_PROVISIONING = "AfterProvisioning";

	private static final String BEFORE_RESPONSE = "BeforeResponse";

	private static final String ON_RESPONSE = "OnResponse";

	private static final String ON_WS_TRUST_RESPONSE = "OnWsTrustResponse";

	private static final String ON_WS_TRUST_ASSERTION = "OnWsTrustAssertion";

	private static final String ON_TOKEN = "OnToken";

	private static final String ON_USER_INFO = "OnUserInfo";

	private static final String ON_MESSAGE = "OnMessage";

	// called from the Groovy script
	public static class HookRecorder {

		public static final List<Object> CALLS = new CopyOnWriteArrayList<>();

	}

	@FunctionalInterface
	interface HookInvoker {

		void invoke(ScriptService scriptService);

	}

	@Autowired
	ScriptService scriptService;

	@MockitoBean
	RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@BeforeEach
	void setup() {
		SamlInitializer.initSamlSubSystem();
		HookRecorder.CALLS.clear();
		scriptService.init(SCRIPT);

		var scripts = Scripts.builder()
							 .scripts(
									 Stream.of(BEFORE_HRD,
												   ON_REQUEST,
												   BEFORE_CP_REQUEST,
												   ON_CP_REQUEST,
												   BEFORE_IDM,
												   AFTER_IDM,
												   AFTER_PROVISIONING,
												   BEFORE_RESPONSE,
												   ON_RESPONSE,
												   ON_WS_TRUST_RESPONSE,
												   ON_WS_TRUST_ASSERTION,
												   ON_TOKEN,
												   ON_USER_INFO,
												   ON_MESSAGE
										   )
										   .map(type -> Script.builder().type(type).name(SCRIPT).build())
										   .toList())
							 .build();

		var relyingParty = RelyingParty.builder().scripts(scripts).build();
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(any(), any())).thenReturn(relyingParty);

		var claimsParty = ClaimsParty.builder().scripts(scripts).build();
		doReturn(claimsParty).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(any(), any());
	}

	@ParameterizedTest
	@MethodSource
	void testHookCoverage(String hook, String expectedIssuer, String expectedScriptType, HookInvoker invoker) {
		invoker.invoke(scriptService);
		assertEquals(HookRecorder.CALLS, List.of(expectedIssuer + "/" + expectedScriptType),
				"Issuer '" + expectedIssuer + "' groovy script '" + SCRIPT + "' not called exactly once for hook " + hook);
	}

	static Stream<Arguments> testHookCoverage() {
		var cpResponse = CpResponse.builder().issuer(ISSUER_CP).rpIssuer(ISSUER_RP).build();
		var rpRequest = RpRequest.builder().rpIssuer(ISSUER_RP).referer(REFERRER).build();
		return Stream.of(
				// Federation hooks (in order of process model)
				Arguments.of("processRequestValidation", ISSUER_RP, ON_REQUEST,
						(HookInvoker) s -> s.processRequestValidation(rpRequest, null)),
				Arguments.of("processHrdSelection", ISSUER_RP, BEFORE_HRD,
						(HookInvoker) s -> s.processHrdSelection(rpRequest)),
				Arguments.of("processRpBeforeCpRequest", ISSUER_RP, BEFORE_CP_REQUEST,
						(HookInvoker) s -> s.processRpBeforeCpRequest(ISSUER_RP, rpRequest)),
				Arguments.of("processCpBeforeCpRequest", ISSUER_RP, BEFORE_CP_REQUEST,
						(HookInvoker) s -> s.processCpBeforeCpRequest(ISSUER_CP, rpRequest)),
				Arguments.of("processRpOnCpRequest", ISSUER_RP, ON_CP_REQUEST,
						(HookInvoker) s -> s.processRpOnCpRequest(ISSUER_RP, rpRequest, null)),
				Arguments.of("processCpOnCpRequest", ISSUER_RP, ON_CP_REQUEST,
						(HookInvoker) s -> s.processCpOnCpRequest(ISSUER_RP, rpRequest, null)),
				Arguments.of("processCpBeforeIdm", ISSUER_RP, BEFORE_IDM,
						(HookInvoker) s -> s.processCpBeforeIdm(cpResponse, null, ISSUER_CP, REFERRER)),
				Arguments.of("processRpBeforeIdm", ISSUER_RP, BEFORE_IDM,
						(HookInvoker) s -> s.processRpBeforeIdm(cpResponse, null, ISSUER_RP, REFERRER)),
				Arguments.of("processCpAfterIdm", ISSUER_RP, AFTER_IDM,
						(HookInvoker) s -> s.processCpAfterIdm(cpResponse, null, ISSUER_CP, REFERRER)),
				Arguments.of("processRpAfterIdm", ISSUER_RP, AFTER_IDM,
						(HookInvoker) s -> s.processRpAfterIdm(cpResponse, null, ISSUER_RP, REFERRER)),
				Arguments.of("processCpAfterProvisioning", ISSUER_RP, AFTER_PROVISIONING,
						(HookInvoker) s -> s.processCpAfterProvisioning(cpResponse, ISSUER_CP)),
				Arguments.of("processRpAfterProvisioning", ISSUER_RP, AFTER_PROVISIONING,
						(HookInvoker) s -> s.processRpAfterProvisioning(cpResponse, ISSUER_RP, REFERRER)),
				Arguments.of("processCpBeforeResponse", ISSUER_RP, BEFORE_RESPONSE,
						(HookInvoker) s -> s.processCpBeforeResponse(cpResponse, null, ISSUER_CP, REFERRER)),
				Arguments.of("processRpBeforeResponse", ISSUER_RP, BEFORE_RESPONSE,
						(HookInvoker) s -> s.processRpBeforeResponse(cpResponse, null, ISSUER_RP, REFERRER)),
				Arguments.of("processCpOnResponse", ISSUER_RP, ON_RESPONSE,
						(HookInvoker) s -> s.processCpOnResponse(cpResponse, null, ISSUER_CP, REFERRER)),
				Arguments.of("processRpOnResponse", ISSUER_RP, ON_RESPONSE,
						(HookInvoker) s -> s.processRpOnResponse(cpResponse, null, ISSUER_RP, REFERRER)),
				Arguments.of("processRpOnToken", ISSUER_RP, ON_TOKEN,
						(HookInvoker) s -> s.processRpOnToken(cpResponse, ISSUER_RP, REFERRER)),
				Arguments.of("processRpOnUserInfo", ISSUER_RP, ON_USER_INFO,
						(HookInvoker) s -> s.processRpOnUserInfo(cpResponse, ISSUER_RP, REFERRER)),
				// WSTrust hooks (having RPRequest binding)
				Arguments.of("processWsTrustOnResponse", ISSUER_RP, ON_WS_TRUST_RESPONSE,
						(HookInvoker) s -> s.processWsTrustOnResponse(cpResponse, null, ISSUER_RP, REFERRER))
				// unsupported not having an RPRequest binding:
				// - processOnMessage
				// - processRpWsTrustOnAssertion
				// - processCpWsTrustOnAssertion
				);
	}

}
