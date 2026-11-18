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

package swiss.trustbroker.monitoring.controller;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.util.ApiSupport;

/**
 * Global service loadbalancer allowing customizable health checks to control data-center access.
 * @since v1.15.0
 */
@RestController
@Slf4j
@AllArgsConstructor
@ConditionalOnBooleanProperty("trustbroker.config.monitoring.enabled")
public class HealthCheckController {

	private final TrustBrokerProperties properties;

	private final ScriptService scriptService;

	/**
	 * Per default return the same as /actuator/health but support a groovy script that allows to do something else.
	 *
	 * @param request provides HTTP servlet request access potentially used by monitoring healthCheckScript via groovy binding
	 * @param response provides HTTP servlet response access defining (expected JSON) response to client
	 */
	@GetMapping(ApiSupport.MONITORING_HEALTH_URL)
	public void globalHealth(HttpServletRequest request, HttpServletResponse response) throws IOException {
		var scriptHook = properties.getMonitoring().getHealthCheckScript();
		if (scriptHook != null) {
			scriptService.processOnMessage(scriptHook);
		}
		else {
			response.setStatus(HttpStatus.SC_OK);
			response.getOutputStream().println("{\"status\":\"UP\"}");
		}
	}

}
