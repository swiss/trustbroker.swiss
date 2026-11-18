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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.IOException;
import java.util.Collections;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import swiss.trustbroker.audit.dto.OidcAuditData;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sso.dto.SloResponseParameters;
import swiss.trustbroker.sso.service.SsoService;

class CustomLogoutSuccessHandlerTest {

	@Test
	void renderResponseWithoutSsoStateRedirectsAndAudits() throws IOException {
		var properties = mock(TrustBrokerProperties.class);
		var relyingPartyDefinitions = mock(RelyingPartyDefinitions.class);
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		var ssoService = mock(SsoService.class);
		var velocityEngine = mock(VelocityEngine.class);
		var handler = new CustomLogoutSuccessHandler(properties, relyingPartyDefinitions, authorizationService, ssoService,
				velocityEngine);

		var request = mock(HttpServletRequest.class);
		doReturn("/oidc/logout").when(request).getRequestURI();
		var response = mock(HttpServletResponse.class);

		var relyingParty = mock(RelyingParty.class);
		doReturn(relyingParty).when(relyingPartyDefinitions)
				.getRelyingPartyByOidcClientId("client-a", null, properties, false);

		try (MockedStatic<OidcSessionSupport> oidcSessionSupport = Mockito.mockStatic(OidcSessionSupport.class)) {
			oidcSessionSupport.when(() -> OidcSessionSupport.getSsoStateDataForClient(ssoService, request, relyingParty,
					"client-a")).thenReturn(null);

			handler.renderResponse("client-a", "https://rp.example.org/logout", "sso-1", "oidc-1", request, response);
		}

		verify(response).sendRedirect("https://rp.example.org/logout");
		verifyNoInteractions(velocityEngine);

		var auditCaptor = ArgumentCaptor.forClass(OidcAuditData.class);
		verify(ssoService).auditLogoutRequestFromRp(any(), any(), any(), any(), auditCaptor.capture());
		assertEquals("client-a", auditCaptor.getValue().getOidcClientId());
		assertEquals("sso-1", auditCaptor.getValue().getSsoSessionId());
		assertEquals("oidc-1", auditCaptor.getValue().getOidcSessionId());
		assertEquals("https://rp.example.org/logout", auditCaptor.getValue().getOidcLogoutUrl());
	}

	@Test
	void renderResponseWithSsoStateAndDirectSloRedirectDiscardsCookieAndRedirects() throws IOException {
		var properties = mock(TrustBrokerProperties.class);
		var relyingPartyDefinitions = mock(RelyingPartyDefinitions.class);
		var authorizationService = mock(CustomOAuth2AuthorizationService.class);
		var ssoService = mock(SsoService.class);
		var velocityEngine = mock(VelocityEngine.class);
		var handler = new CustomLogoutSuccessHandler(properties, relyingPartyDefinitions, authorizationService, ssoService,
				velocityEngine);

		var request = mock(HttpServletRequest.class);
		doReturn("/oidc/logout").when(request).getRequestURI();
		var response = mock(HttpServletResponse.class);

		var relyingParty = mock(RelyingParty.class);
		doReturn(relyingParty).when(relyingPartyDefinitions)
				.getRelyingPartyByOidcClientId("client-a", null, properties, false);

		var stateData = mock(StateData.class);
		doReturn(true).when(stateData).hasSsoState();
		var ssoState = mock(SsoState.class);
		doReturn(Collections.emptySet()).when(ssoState).getSsoParticipants();
		doReturn(ssoState).when(stateData).getSsoState();
		doReturn(null).when(stateData).getCpResponse();
		var expiredCookie = new Cookie("_sso", "");
		doReturn(expiredCookie).when(ssoService).generateExpiredCookie(stateData);
		doReturn("https://computed.example.org/logout").when(ssoService)
				.computeOidcSingleLogoutUrl("https://rp.example.org/logout", null, relyingParty);
		doReturn(new SloResponseParameters(Collections.emptyMap(), true, "https://post-slo.example.org/redirect"))
				.when(ssoService)
				.buildSloResponseParameters(relyingParty, null, Collections.emptySet(), null, "oidc-1",
						"https://computed.example.org/logout");

		try (MockedStatic<OidcSessionSupport> oidcSessionSupport = Mockito.mockStatic(OidcSessionSupport.class)) {
			oidcSessionSupport.when(() -> OidcSessionSupport.getSsoStateDataForClient(ssoService, request, relyingParty,
					"client-a")).thenReturn(stateData);

			handler.renderResponse("client-a", "https://rp.example.org/logout", "sso-1", "oidc-1", request, response);
		}

		verify(response).addCookie(expiredCookie);
		verify(response).sendRedirect("https://post-slo.example.org/redirect");

		var auditCaptor = ArgumentCaptor.forClass(OidcAuditData.class);
		verify(ssoService).auditLogoutRequestFromRp(any(), any(), any(), any(), auditCaptor.capture());
		assertEquals("https://computed.example.org/logout", auditCaptor.getValue().getOidcLogoutUrl());
	}
}

