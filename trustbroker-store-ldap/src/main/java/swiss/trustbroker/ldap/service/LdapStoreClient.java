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

package swiss.trustbroker.ldap.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.naming.directory.SearchControls;

import io.micrometer.core.annotation.Timed;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.IdmQueryUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;

@Service
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.ldap.enabled")
public class LdapStoreClient {

	private final Map<String, Supplier<LdapTemplate>> ldapTemplates;

	private final TrustBrokerProperties trustBrokerProperties;

	@Autowired
	public LdapStoreClient(@Qualifier("ldapTemplates") Map<String, Supplier<LdapTemplate>> ldapTemplates,
			TrustBrokerProperties trustBrokerProperties) {
		this.ldapTemplates = ldapTemplates;
		this.trustBrokerProperties = trustBrokerProperties;
	}

	@Timed("ldap")
	@Traced
	public List<Map<String, List<String>>> search(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequest idmQuery,
	                                              List<Map<String, List<String>>> attributes, IdmResult result) {
		final var appFilter = idmQuery.getAppFilter();
		final var serviceName = IdmQueryUtil.resolveStoreName(idmQuery, relyingPartyConfig.getId());
		final var ldapTemplate = resolveTemplate(serviceName, relyingPartyConfig.getId());
		final var formattedQuery = queryFilterFormatter(appFilter, cpResponse, relyingPartyConfig.getId(), attributes, result);
		final var base = getQueryBase(idmQuery.getSubResource(), relyingPartyConfig);
		log.info("IDM call ({}): issuer={} relyingPartyIssuerId={} serviceName={} base={} query={} ",
				ExternalStores.LDAP, cpResponse.getIssuerId(), relyingPartyConfig.getId(), serviceName, base, formattedQuery);
		final var attrs = ldapTemplate.search(base, formattedQuery, SearchControls.SUBTREE_SCOPE, new String[]{ "*" }, new LdapAttributeMapper());
		log.debug("IDM search ({}): for rp={} with query={} results={}", ExternalStores.LDAP, relyingPartyConfig.getId(), formattedQuery, attrs);

		return attrs;
	}

	private LdapTemplate resolveTemplate(String serviceName, String rpId) {
		var templateSupplier = ldapTemplates.get(serviceName);
		if (templateSupplier != null) {
			return templateSupplier.get();
		}
		for (var entry : ldapTemplates.entrySet()) {
			if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(serviceName)) {
				return entry.getValue().get();
			}
		}
		throw new TechnicalException(String.format(
				"Unknown LDAP store '%s' for rp=%s. Configure trustbroker.config.ldap.stores.%s or use one of: %s",
				serviceName, rpId, serviceName, ldapTemplates.keySet()));
	}

	String getQueryBase(String subResource, RelyingPartyConfig relyingPartyConfig) {
		if (subResource == null || subResource.isEmpty()) {
			throw new TechnicalException(String.format("Missing subResource for rp=%s HINT: Set RelyingParty.IDMLookup.IDMQuery.SubResource", relyingPartyConfig.getId()));
		}
		return subResource;
	}

	String queryFilterFormatter(String appFilter, CpResponseData cpResponse, String rpId, List<Map<String, List<String>>> attributes,
	                            IdmResult result) {
		if (appFilter == null || appFilter.isEmpty()) {
			throw new TechnicalException(String.format(
					"AppFilter is null or empty for rp=%s HINT: configure IDMLookup.IDMQuery.AppFilter", rpId));
		}
		var ldapUndefined = trustBrokerProperties.getLdap().getUndefined();
		// Extract placeholders
		var pattern = Pattern.compile(IdmQueryUtil.PLACEHOLDER_PATTERN);
		var matcher = pattern.matcher(appFilter);

		List<String> placeholders = new ArrayList<>();

		while (matcher.find()) {
			placeholders.add(matcher.group(1));
		}

		// Fill up placeholders
		Map<String, Object> params = new HashMap<>();

		for (var placeholder : placeholders) {
			if (placeholder == null) {
				log.error("Placeholder is null in appFilter={}", appFilter);
				continue;
			}
			var placeholderValues = getPlaceholderValues(placeholder, cpResponse, attributes, result);
			var placeholderValue = getEncodedPlaceHolderValue(placeholder, placeholderValues, ldapUndefined);
			params.put(placeholder, placeholderValue);
		}

		return StringSubstitutor.replace(appFilter, params, "${", "}");
	}

	static String getEncodedPlaceHolderValue(String placeholder, List<String> placeholderValues, String ldapUndefined) {
		var placeholderValue = new StringBuilder();

		if (placeholder.startsWith(IdmQueryUtil.LIST_PLACEHOLDER)) {
			var claimName = getListPlaceholderClaim(placeholder);
			for (String value : placeholderValues) {
				var encodedValue = LdapEncoder.filterEncode(value);
				placeholderValue.append('(').append(claimName).append("=").append(encodedValue).append(')');
			}
		}
		else if (!placeholderValues.isEmpty()) {
			if (placeholderValues.getFirst() == null) {
				return ldapUndefined;
			}
			return LdapEncoder.filterEncode(placeholderValues.getFirst());
		}
		else {
			throw new TechnicalException("Unsupported placeholder values: " + placeholderValues);
		}
		return placeholderValue.toString();
	}

	private static String getListPlaceholderClaim(String placeholder) {
		String[] elements = placeholder.split(IdmQueryUtil.COLON);
		if (elements.length != 4) {
			throw new TechnicalException("Expected LIST placeholder format: " + placeholder);
		}
		return elements[3];
	}

	List<String> getPlaceholderValues(String placeholder, CpResponseData cpResponse, List<Map<String, List<String>>> attributeNameListMap, IdmResult result) {
		var undefinedValue = trustBrokerProperties.getLdap().getUndefined();
		return IdmQueryUtil.getPlaceholderValues(placeholder, cpResponse, attributeNameListMap, result,
				ExternalStores.LDAP.name(), undefinedValue);
	}

}
