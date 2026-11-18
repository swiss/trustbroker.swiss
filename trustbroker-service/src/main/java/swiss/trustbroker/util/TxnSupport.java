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

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TxnSupport {

	// Support for relying party TX tracking e.g. via a custom rp_txn_id parameter or the OIDC recommended state tracking
	// If trustbroker.config.rpTxnIdParameter is not set, the mechanism is disabled.
	// The rpTxnId is tracked in AuditLogger and if picked also as a attribute or claim in the AuditLogger.
	// To achieve the latter use a configuration like this:
	//     application.yml: trustbroker.config.rpTxnIdParameter: rp_txn_id
	//     SetupRP: <Definition name="RpTxnId" ... oidcNames="rp_txn_id" scope="txn" source="PROPS"/>
	// Instead of inventing a custom parameter the OIDC 'state' could be used.
	//
	public static String getRpTxnIdFromRequest(HttpServletRequest request, TrustBrokerProperties properties) {
		var rpTxnIdParameter = properties.getRpTxnIdParameter();
		if (StringUtils.isEmpty(rpTxnIdParameter)) {
			return null;
		}
		return WebUtil.getParameter(rpTxnIdParameter, request);
	}

}
