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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import tools.jackson.core.JsonPointer;
import tools.jackson.databind.JsonNode;

@Component
@Slf4j
@ConditionalOnBooleanProperty("trustbroker.config.rest.enabled")
public class RestResponseHandler {

	public List<Map<String, List<String>>> mapResponse(JsonNode jsonNode, RelyingPartyConfig relyingPartyConfig,
			IdmRequest idmRequest, String subResource) {
		var resources = extractResourceNodes(jsonNode, subResource);
		var mappings = effectiveMappings(relyingPartyConfig, idmRequest);
		if (mappings.isEmpty()) {
			log.debug("No REST attribute mappings configured for query={}", idmRequest.getName());
			return List.of();
		}

		List<Map<String, List<String>>> mappedResources = new ArrayList<>();
		for (var resource : resources) {
			Map<String, List<String>> attributeMap = new LinkedHashMap<>();
			for (var mapping : mappings.entrySet()) {
				var values = extractPathValues(resource, mapping.getValue());
				if (!values.isEmpty()) {
					attributeMap.put(mapping.getKey(), values);
				}
			}
			if (!attributeMap.isEmpty()) {
				mappedResources.add(attributeMap);
			}
		}
		return mappedResources;
	}

	Map<String, String> effectiveMappings(RelyingPartyConfig relyingPartyConfig, IdmRequest idmRequest) {
		List<AttributeName> attributes = new ArrayList<>();

		if (idmRequest.getAttributeSelection() != null) {
			attributes.addAll(idmRequest.getAttributeSelection());
		}

		getRpAttributes(relyingPartyConfig, attributes, idmRequest);

		if (attributes.isEmpty()) {
			return Map.of();
		}

		return getStoreMappers(attributes);
	}

	@Nonnull
	private static Map<String, String> getStoreMappers(List<AttributeName> attributes) {
		Map<String, String> mappings = new LinkedHashMap<>();
		for (AttributeName attributeName : attributes) {
			if (attributeName == null || StringUtils.isEmpty(attributeName.getName())) {
				continue;
			}
			String jsonPointer = attributeName.getStoreMapper();
			if (StringUtils.isEmpty(jsonPointer)) {
				jsonPointer = toRootPointer(attributeName.getName());
			}
			validateJsonPointer(jsonPointer, "attribute '" + attributeName.getName() + "'");
			mappings.put(attributeName.getName(), jsonPointer);
		}
		return mappings;
	}

	private static void getRpAttributes(RelyingPartyConfig relyingPartyConfig, List<AttributeName> attributes, IdmRequest idmRequest) {
		if (relyingPartyConfig instanceof RelyingParty relyingParty) {
			var claimsSelection = relyingParty.getClaimsSelection();
			if (claimsSelection != null && claimsSelection.getDefinitions() != null) {
				var storeName = idmRequest.getName() != null ? idmRequest.getName() : ExternalStores.REST.name();
				var restStore = ClaimSource.IDM.name() + ClaimSourceUtil.SEPARATOR + ExternalStores.REST.name();
				var restStoreWithName = ClaimSource.IDM.name() + ClaimSourceUtil.SEPARATOR + storeName;
				for (Definition def : claimsSelection.getDefinitions()) {
					if (def != null && (ClaimSource.IDM.name().equals(def.getSource()) ||
							restStore.equals(def.getSource()) || restStoreWithName.equals(def.getSource()))) {
						attributes.add(def);
					}
				}
			}
		}
	}

	List<JsonNode> extractResourceNodes(JsonNode parsedJson, String responseRootPath) {
		if (parsedJson == null || parsedJson.isMissingNode()) {
			return List.of();
		}
		if (StringUtils.isNotEmpty(responseRootPath)) {
			validateJsonPointer(responseRootPath, "responseRootPath");
			var rootObjects = extractPathObjects(parsedJson, responseRootPath);
			if (!rootObjects.isEmpty()) {
				return flattenResources(rootObjects);
			}
		}
		if (parsedJson.isArray()) {
			List<JsonNode> resources = new ArrayList<>();
			parsedJson.forEach(resources::add);
			return resources;
		}
		return List.of(parsedJson);
	}

	private static List<JsonNode> flattenResources(List<JsonNode> rootObjects) {
		List<JsonNode> resources = new ArrayList<>();
		for (var root : rootObjects) {
			if (root.isArray()) {
				root.forEach(resources::add);
			}
			else {
				resources.add(root);
			}
		}
		return resources;
	}

	List<String> extractPathValues(JsonNode source, String pathExpression) {
		var objects = extractPathObjects(source, pathExpression);
		var values = new LinkedHashSet<String>();
		for (var object : objects) {
			collectScalarValues(object, values);
		}
		return new ArrayList<>(values);
	}

	private static void collectScalarValues(JsonNode node, LinkedHashSet<String> values) {
		if (node == null || node.isMissingNode()) {
			return;
		}
		if (node.isArray()) {
			node.forEach(element -> collectScalarValues(element, values));
			return;
		}
		if (node.isString()) {
			values.add(node.asString());
			return;
		}
		throw new TechnicalException(String.format("Unsupported JSON node type for REST attribute mapping=%s - "
				+ "only string or list values are allowed.", node.getNodeType()));
	}

	List<JsonNode> extractPathObjects(JsonNode source, String pathExpression) {
		if (source == null || source.isMissingNode() || pathExpression == null) {
			return List.of();
		}
		var pointer = pathExpression.trim();
		if (pointer.isEmpty()) {
			return List.of(source);
		}
		validateJsonPointer(pointer, "path expression");
		var resolved = source.at(pointer);
		if (resolved == null || resolved.isMissingNode()) {
			return List.of();
		}
		if (resolved.isArray()) {
			List<JsonNode> items = new ArrayList<>();
			resolved.forEach(items::add);
			return items;
		}
		return List.of(resolved);
	}

	private static void validateJsonPointer(String pointer, String sourceLabel) {
		try {
			JsonPointer.compile(pointer);
		}
		catch (IllegalArgumentException ex) {
			throw new TechnicalException(
					String.format("Invalid JSON Pointer in label=\"%s\" pointer=\"%s\"", sourceLabel, pointer), ex);
		}
	}

	private static String toRootPointer(String token) {
		var escaped = token.replace("~", "~0").replace("/", "~1");
		return "/" + escaped;
	}

}
