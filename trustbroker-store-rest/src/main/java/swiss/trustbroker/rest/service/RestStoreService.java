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

package swiss.trustbroker.rest.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.util.IdmAttributeUtil;

@Service
@Slf4j
@AllArgsConstructor
@ConditionalOnBooleanProperty("trustbroker.config.rest.enabled")
public class RestStoreService implements IdmQueryService {

	private final RestStoreClient restStoreClient;

	@Override
	public boolean getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
			IdmRequest idmRequest, IdmStatusPolicyCallback statusPolicyCallback, Map<String, Object> state, IdmResult result) {
		var storeName = idmRequest.getName() != null ? idmRequest.getName() : ExternalStores.REST.name();
		var attrs = restStoreClient.search(relyingPartyConfig, cpResponse, idmRequest, List.of(), result);
		var mappedAttrs = aggregateAndFindAttributes(attrs, storeName, relyingPartyConfig, idmRequest);
		result.getUserDetails().putAll(mappedAttrs);
		result.setLastQueryUserDetailsCount(mappedAttrs.size());
		result.addOriginalUserDetailsCount(mappedAttrs.size());
		if (log.isInfoEnabled()) {
			log.info("IDM result ({}): Called REST endpoint with query={} issuer={} nameID={} resultCount={} success={}",
					ExternalStores.REST.name(), idmRequest.getName(), cpResponse.getIssuerId(), cpResponse.getNameId(),
					mappedAttrs.size(), !mappedAttrs.isEmpty());
		}
		return true;
	}

	private static Map<AttributeName, List<String>> aggregateAndFindAttributes(List<Map<String, List<String>>> attrs,
			String queryName, RelyingPartyConfig relyingPartyConfig, IdmRequest idmRequest) {
		Map<String, List<String>> aggregatedAttributes = new HashMap<>();
		for (var attrMap : attrs) {
			for (var entry : attrMap.entrySet()) {
				aggregatedAttributes.computeIfAbsent(entry.getKey(), key -> new ArrayList<>()).addAll(entry.getValue());
			}
		}
		for (var entry : aggregatedAttributes.entrySet()) {
			entry.setValue(new ArrayList<>(new HashSet<>(entry.getValue())));
		}
		var attributeSelection = IdmAttributeUtil.getIdmAttributeSelection(relyingPartyConfig, idmRequest);
		return IdmAttributeUtil.getAttributesForQueryResponse(aggregatedAttributes, queryName, attributeSelection);
	}

	@Override
	public Integer getServiceDefaultOrder() {
		return Integer.MAX_VALUE;
	}

	@Override
	public String getStoreName() {
		return ExternalStores.REST.name();
	}

}

