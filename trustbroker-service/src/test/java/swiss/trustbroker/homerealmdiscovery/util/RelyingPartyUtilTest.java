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

package swiss.trustbroker.homerealmdiscovery.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.QueryControl;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.StatusPolicy;
import swiss.trustbroker.saml.dto.CpResponse;

class RelyingPartyUtilTest {

	@Test
	void testReferrerUrlHandling() {
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer(null).size());
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer("bullshit").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("http://host").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("http://host:80").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host:443").size());
		assertEquals(2, RelyingPartyUtil.getIdsFromReferer("https://host:443/").size());
		assertEquals(3, RelyingPartyUtil.getIdsFromReferer("https://host:443/path").size());
		assertEquals(3, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path/").size());
		assertEquals(4, RelyingPartyUtil.getIdsFromReferer("https://host:443/path/path/path").size());
		assertEquals(0, RelyingPartyUtil.getIdsFromReferer("https:/host:443/path/path/path").size());
		assertEquals("x/1/2", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(1));
		assertEquals("x/1", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(2));
		assertEquals("x", RelyingPartyUtil.getIdsFromReferer("http://x/1/2/3").get(3));
	}

	@Test
	void stopOnUserFoundDoesNotStopWhenNoPreviousPrimaryResultExists() {
		var firstService = Mockito.mock(IdmQueryService.class);
		var secondService = Mockito.mock(IdmQueryService.class);
		when(firstService.getStoreName()).thenReturn("FIRST");
		when(secondService.getStoreName()).thenReturn("SECOND");
		when(firstService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, swiss.trustbroker.api.idm.dto.IdmResult.class);
			result.getUserDetails().put(new Definition("uid"), List.of("user-1"));
			result.setLastQueryUserDetailsCount(1);
			result.addOriginalUserDetailsCount(1);
			return true;
		});

		var lookup = IdmLookup.builder()
				.queries(List.of(
						IdmQuery.builder().id("q1").store("FIRST").statusPolicy(StatusPolicy.STOP_ON_USER_FOUND).build(),
						IdmQuery.builder().id("q2").store("SECOND").build()))
				.build();
		var cpResponse = CpResponse.builder().idmLookup(lookup).build();
		var relyingParty = RelyingParty.builder().id("rp1").build();

		var result = RelyingPartyUtil.performIdmLookups(cpResponse, relyingParty, false, new IdmStatusPolicyCallback() {},
				List.of(firstService, secondService));

		assertTrue(result.isPresent());
		verify(firstService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(secondService, times(0)).getAttributes(any(), any(), any(), any(), any(), any());
	}

	@Test
	void continueLoopWhenPolicyIsNotStopOnUserFound() {
		var firstService = Mockito.mock(IdmQueryService.class);
		var secondService = Mockito.mock(IdmQueryService.class);
		when(firstService.getStoreName()).thenReturn("FIRST");
		when(secondService.getStoreName()).thenReturn("SECOND");
		when(firstService.getAttributesAudited(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, swiss.trustbroker.api.idm.dto.IdmResult.class);
			result.getUserDetails().put(new Definition("uid"), List.of("user-1"));
			result.setLastQueryUserDetailsCount(1);
			result.addOriginalUserDetailsCount(1);
			return true;
		});
		when(secondService.getAttributesAudited(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(0);
			return true;
		});

		var lookup = IdmLookup.builder()
				.queries(List.of(
						IdmQuery.builder().id("q1").store("FIRST").statusPolicy(StatusPolicy.FETCH_ACTIVE_ONLY).build(),
						IdmQuery.builder().id("q2").store("SECOND").build()))
				.build();
		var cpResponse = CpResponse.builder().idmLookup(lookup).build();
		var relyingParty = RelyingParty.builder().id("rp1").build();

		var result = RelyingPartyUtil.performIdmLookups(cpResponse, relyingParty, true, new IdmStatusPolicyCallback() {},
				List.of(firstService, secondService));

		assertTrue(result.isPresent());
		verify(firstService, times(1)).getAttributesAudited(any(), any(), any(), any(), any(), any());
		verify(secondService, times(1)).getAttributesAudited(any(), any(), any(), any(), any(), any());
	}

	@Test
	void stopOnUserFoundStopsWhenPreviousPrimaryResultExists() {
		var firstService = Mockito.mock(IdmQueryService.class);
		var secondService = Mockito.mock(IdmQueryService.class);
		var thirdService = Mockito.mock(IdmQueryService.class);
		when(firstService.getStoreName()).thenReturn("FIRST");
		when(secondService.getStoreName()).thenReturn("SECOND");
		when(thirdService.getStoreName()).thenReturn("THIRD");
		when(firstService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.getUserDetails().put(new Definition("uid"), List.of("user-1"));
			result.setLastQueryUserDetailsCount(1);
			result.addOriginalUserDetailsCount(1);
			return true;
		});
		when(secondService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(1);
			return true;
		});
		when(thirdService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(0);
			return true;
		});

		var lookup = IdmLookup.builder()
				.queries(List.of(
						IdmQuery.builder().id("q1").store("FIRST").statusPolicy(StatusPolicy.FETCH_ACTIVE_ONLY).build(),
						IdmQuery.builder().id("q2").store("SECOND").statusPolicy(StatusPolicy.STOP_ON_USER_FOUND).build(),
						IdmQuery.builder().id("q3").store("THIRD").build()))
				.build();
		var cpResponse = CpResponse.builder().idmLookup(lookup).build();
		var relyingParty = RelyingParty.builder().id("rp1").build();

		var result = RelyingPartyUtil.performIdmLookups(cpResponse, relyingParty, false, new IdmStatusPolicyCallback() {},
				List.of(firstService, secondService, thirdService));

		assertTrue(result.isPresent());
		verify(firstService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(secondService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(thirdService, never()).getAttributes(any(), any(), any(), any(), any(), any());
	}

	@Test
	void stopOnUserFoundWhenCurrentQueryChangesExistingUserDetails() {
		var firstService = Mockito.mock(IdmQueryService.class);
		var secondService = Mockito.mock(IdmQueryService.class);
		var thirdService = Mockito.mock(IdmQueryService.class);
		when(firstService.getStoreName()).thenReturn("FIRST");
		when(secondService.getStoreName()).thenReturn("SECOND");
		when(thirdService.getStoreName()).thenReturn("THIRD");
		when(firstService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.getUserDetails().put(new Definition("uid"), List.of("user-1"));
			result.setLastQueryUserDetailsCount(1);
			result.addOriginalUserDetailsCount(1);
			return true;
		});
		when(secondService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.getUserDetails().put(new Definition("uid"), List.of("user-2"));
			result.setLastQueryUserDetailsCount(1);
			result.addOriginalUserDetailsCount(1);
			return true;
		});
		when(thirdService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(0);
			return true;
		});

		var lookup = IdmLookup.builder()
				.queries(List.of(
						IdmQuery.builder().id("q1").store("FIRST").statusPolicy(StatusPolicy.FETCH_ACTIVE_ONLY).build(),
						IdmQuery.builder().id("q2").store("SECOND").statusPolicy(StatusPolicy.STOP_ON_USER_FOUND).build(),
						IdmQuery.builder().id("q3").store("THIRD").build()))
				.build();
		var cpResponse = CpResponse.builder().idmLookup(lookup).build();
		var relyingParty = RelyingParty.builder().id("rp1").build();

		var result = RelyingPartyUtil.performIdmLookups(cpResponse, relyingParty, false, new IdmStatusPolicyCallback() {},
				List.of(firstService, secondService, thirdService));

		assertTrue(result.isPresent());
		verify(firstService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(secondService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(thirdService, never()).getAttributes(any(), any(), any(), any(), any(), any());
	}

	@Test
	void additionalQueryWithStopOnUserFoundStopsWhenPreviousPrimaryFoundUser() {
		var firstService = Mockito.mock(IdmQueryService.class);
		var secondService = Mockito.mock(IdmQueryService.class);
		var thirdService = Mockito.mock(IdmQueryService.class);
		when(firstService.getStoreName()).thenReturn("FIRST");
		when(secondService.getStoreName()).thenReturn("SECOND");
		when(thirdService.getStoreName()).thenReturn("THIRD");
		when(firstService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(1);
			result.getUserDetails().put(new Definition("uid"), List.of("user-1"));
			return true;
		});
		when(secondService.getAttributes(any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
			var result = invocation.getArgument(5, IdmResult.class);
			result.setLastQueryUserDetailsCount(0);
			result.getUserDetails().put(new Definition("phone"), List.of("111"));
			return true;
		});
		when(thirdService.getAttributes(any(), any(), any(), any(), any(), any())).thenReturn(true);

		var lookup = IdmLookup.builder()
				.queries(List.of(
						IdmQuery.builder().id("q1").store("FIRST")
								.statusPolicy(StatusPolicy.FETCH_ACTIVE_ONLY)
																							.queryControl(QueryControl.PRIMARY)
								.build(),
						IdmQuery.builder().id("q2").store("SECOND")
								.statusPolicy(StatusPolicy.STOP_ON_USER_FOUND)
																							.queryControl(QueryControl.ADDITIONAL)
								.build(),
						IdmQuery.builder().id("q3").store("THIRD").build()))
				.build();
		var cpResponse = CpResponse.builder().idmLookup(lookup).build();
		var relyingParty = RelyingParty.builder().id("rp1").build();

		var result = RelyingPartyUtil.performIdmLookups(cpResponse, relyingParty, false, new IdmStatusPolicyCallback() {},
				List.of(firstService, secondService, thirdService));

		assertTrue(result.isPresent());
		assertEquals(1, result.get().getLastQueryUserDetailsCount());
		verify(firstService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(secondService, times(1)).getAttributes(any(), any(), any(), any(), any(), any());
		verify(thirdService, never()).getAttributes(any(), any(), any(), any(), any(), any());
	}

}
