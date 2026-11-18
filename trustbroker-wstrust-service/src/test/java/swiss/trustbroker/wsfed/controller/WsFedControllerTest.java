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

package swiss.trustbroker.wsfed.controller;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.WsFedConfig;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.wsfed.dto.WsFedAction;
import swiss.trustbroker.wsfed.service.WsFedService;
import swiss.trustbroker.wsfed.util.WsFedUtil;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		WsFedController.class
})
@AutoConfigureMockMvc
@TestPropertySource(properties = "trustbroker.config.wsfed.enabled=true")
class WsFedControllerTest {

	private static final String ALLOWED_NETWORK = "INTRANET";

	private static final String BLOCKED_NETWORK = "INTERNET";

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private WsFedService wsFedService;

	@Autowired
	private WsFedController wsFedController;

	@Autowired
	private WebApplicationContext webApplicationContext;

	private MockMvc mockMvc;

	private WsFedConfig wsFedConfig;

	private NetworkConfig networkConfig;

	@BeforeEach
	void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
		wsFedConfig = new WsFedConfig();
		when(trustBrokerProperties.getWsfed()).thenReturn(wsFedConfig);
		networkConfig = new NetworkConfig();
		when(trustBrokerProperties.getNetwork()).thenReturn(networkConfig);
	}

	@Test
	void testAllowed() throws Exception {
		when(wsFedService.isWsFed(any())).thenReturn(true);
		this.mockMvc.perform(get(givenWsFedSignIn()))
		            .andExpect(status().isOk());
		verify(wsFedService).processWsFedRequest(any(), any(), any());
	}

	@ParameterizedTest
	@CsvSource(value = {
			ALLOWED_NETWORK + ",true",
			BLOCKED_NETWORK + ",false"
	})
	void testNetworkAllowed(String network, boolean enforce) throws Exception {
		when(wsFedService.isWsFed(any())).thenReturn(true);
		wsFedConfig.setAllowedNetworks(List.of(ALLOWED_NETWORK));
		wsFedConfig.setEnforceNetwork(enforce);
		this.mockMvc.perform(get(givenWsFedSignIn())
		            .header(networkConfig.getNetworkHeader(), network))
		            .andExpect(status().isOk());
		verify(wsFedService).processWsFedRequest(any(), any(), any());
	}

	@Test
	void testNetworkNotAllowed() {
		when(wsFedService.isWsFed(any())).thenReturn(true);
		wsFedConfig.setAllowedNetworks(List.of(ALLOWED_NETWORK));
		var ex = assertThrows(ServletException.class, () -> mockMvc.perform(
				get(givenWsFedSignIn())
						.header(networkConfig.getNetworkHeader(), BLOCKED_NETWORK)));
		assertThat(ex.getCause(), instanceOf(RequestDeniedException.class));
		assertThat(((RequestDeniedException) ex.getCause()).getInternalMessage(), containsString("WS-Fed not allowed from client network"));
	}

	@Test
	void testNotWsFed() {
		when(wsFedService.isWsFed(any())).thenReturn(false);
		var ex = assertThrows(ServletException.class, () -> mockMvc.perform(get(givenWsFedSignIn())));
		assertThat(ex.getCause(), instanceOf(RequestDeniedException.class));
		assertThat(((RequestDeniedException) ex.getCause()).getInternalMessage(), containsString("Expected WS-Fed request"));
	}

	private static String givenWsFedSignIn() {
		return  ApiSupport.WSFED_API + '?' + WsFedUtil.ACTION + '=' + WsFedAction.ACTION_SIGN_IN.getAction();
	}

}
