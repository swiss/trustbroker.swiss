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

package swiss.trustbroker.common.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Utility class for IDM query placeholder resolution shared between LDAP and REST clients.
 */
@Slf4j
public class IdmQueryUtil {

	/**
	 * Regex pattern to match placeholders like ${attributeName}
	 */
	public static final String PLACEHOLDER_PATTERN = "\\$\\{([^}]+)}";

	/**
	 * Constant for colon separator used in placeholder parsing.
	 */
	public static final String COLON = ":";

	/**
	 * Constant for LIST placeholder prefix used in IDM query placeholders.
	 */
	public static final String LIST_PLACEHOLDER = "LIST";

	/**
	 * Constant for the subjectNameId placeholder.
	 */
	public static final String SUBJECT_NAME_ID = "subjectNameId";

	private IdmQueryUtil() {
		// utility class
	}

	/**
	 * Resolve service/store name from IDMQuery by trying connection attribute first, then falling back to store.
	 *
	 * @param idmQuery The IDM query configuration
	 * @param rpId The relying party ID (used in error messages)
	 * @return The resolved service name
	 * @throws TechnicalException if neither connection nor store attributes are specified
	 */
	public static String resolveStoreName(IdmRequest idmQuery, String rpId) {
		// Use connection if specified, otherwise fall back to store
		var storeName = idmQuery != null ? idmQuery.getConnection() : null;
		if (StringUtils.isEmpty(storeName)) {
			storeName = idmQuery != null ? idmQuery.getStore() : null;
		}
		if (StringUtils.isEmpty(storeName)) {
			throw new TechnicalException(String.format(
					"Missing IDMQuery.connection or IDMQuery.store for rp=%s: required to resolve service name", rpId));
		}
		return storeName;
	}

	/**
	 * Get placeholder values from CPResponse attributes or IDM results.
	 *
	 * @param placeholder The placeholder name
	 * @param cpResponse CPResponse data
	 * @param attributeNameListMap Previous attribute results (from earlier IDM queries)
	 * @param result Current IDM result
	 * @param currentStoreName Current store name (e.g., "LDAP", "REST")
	 * @param undefinedValue Value to use when attribute is not found
	 * @return List of resolved values
	 */
	public static List<String> getPlaceholderValues(String placeholder, CpResponseData cpResponse,
			List<Map<String, List<String>>> attributeNameListMap, IdmResult result,
			String currentStoreName, String undefinedValue) {
		if (placeholder == null) {
			return Collections.emptyList();
		}
		List<String> placeholderValues = new ArrayList<>();
		if (SUBJECT_NAME_ID.equals(placeholder)) {
			placeholderValues.add(cpResponse.getNameId());
		}
		else if (isIdmClaim(placeholder)) {
			return getUserDetails(placeholder, attributeNameListMap, result, currentStoreName, undefinedValue);
		}
		else if (isPropertiesClaim(placeholder)) {
			return getProperties(placeholder, result, undefinedValue);
		}
		else {
			placeholderValues.add(cpResponse.getAttribute(placeholder));
		}
		return placeholderValues;
	}

	/**
	 * Check if placeholder is an IDM claim (contains IDM source).
	 */
	public static boolean isIdmClaim(String placeholder) {
		return placeholder.lastIndexOf(COLON) != -1 && placeholder.contains("IDM");
	}

	/**
	 * Check if placeholder is a properties claim (contains PROPS source).
	 */
	public static boolean isPropertiesClaim(String placeholder) {
		return placeholder.lastIndexOf(COLON) != -1 && placeholder.contains("PROPS");
	}

	/**
	 * Get attribute values from list of attribute maps.
	 */
	public static List<String> getAttributeFromListMap(String claimName, List<Map<String, List<String>>> attributes) {
		List<String> attributeValues = new ArrayList<>();
		for (var map : attributes) {
			if (map.containsKey(claimName)) {
				attributeValues.addAll(map.get(claimName));
			}
		}
		return attributeValues;
	}

	/**
	 * Get user details from IDM results based on placeholder.
	 * Example placeholder formats:
	 * - IDM:REST:employeeNumber
	 * - IDM:LDAP:email
	 * - LIST:IDM:LDAP:memberOf
	 *
	 * @param placeholder Placeholder string
	 * @param attributeNameListMap Previous attribute results from same store
	 * @param result Current IDM result
	 * @param currentStoreName Current store name (e.g., "LDAP", "REST")
	 * @param undefinedValue Value to use when attribute is not found
	 * @return List of resolved attribute values
	 */
	public static List<String> getUserDetails(String placeholder, List<Map<String, List<String>>> attributeNameListMap,
			IdmResult result, String currentStoreName, String undefinedValue) {
		// Example: placeholder in form of `LIST:IDM:<query_name>:<definition_name>` or `IDM:<query_name>:<definition_name>`
		final var lastColonIndex = placeholder.lastIndexOf(COLON);
		final var claimName = placeholder.substring(lastColonIndex + 1);
		final var source = resolveSource(placeholder, lastColonIndex);

		List<String> list = new ArrayList<>();

		// Check if requesting from LDAP store's previous results
		if (ExternalStores.LDAP.name().equals(currentStoreName) && (attributeNameListMap != null && !attributeNameListMap.isEmpty())) {
			list = getAttributeFromListMap(claimName, attributeNameListMap);
		}

		// Check if requesting from other IDM sources
		if (list.isEmpty()) {
			list = getUserDetailsForSource(result, claimName, source);
		}

		if (list.isEmpty()) {
			return List.of(undefinedValue);
		}
		return list.stream().distinct().map(value -> value != null ? value : undefinedValue).toList();
	}

	/**
	 * Get user detail attribute values from IDM results for a specific source.
	 *
	 * <p>Matches {@code claimName} against both attribute name and namespace URI, and only returns values
	 * where the attribute source equals the provided {@code source} (for example {@code IDM:LDAP} or
	 * {@code IDM:REST}).</p>
	 *
	 * @param result Current IDM result containing user details
	 * @param claimName Attribute name or namespace URI to resolve
	 * @param source Source identifier to filter matching attributes
	 * @return List of matching values, or an empty list when no match is found
	 */
	public static List<String> getUserDetailsForSource(IdmResult result, String claimName, String source) {
		List<String> list = new ArrayList<>();
		if (result != null && result.getUserDetails() != null) {
			result.getUserDetails().forEach((key, value) -> {
				if (key != null) {
					boolean sameName = claimName.equals(key.getName()) || claimName.equals(key.getNamespaceUri());
					boolean sameSource = key.getSource() != null && key.getSource().equals(source);
					if (sameName && sameSource) {
						list.addAll(value);
					}
				}
			});
		}
		return list;
	}

	/**
	 * Resolve the source component from a placeholder string by stripping the LIST: prefix if present.
	 * Example: "LIST:IDM:REST" -> "IDM:REST", "IDM:REST" -> "IDM:REST"
	 *
	 * @param placeholder Placeholder string
	 * @param lastColonIndex Index of the last colon in the placeholder
	 * @return Resolved source string with LIST: prefix removed if present
	 */
	private static String resolveSource(String placeholder, int lastColonIndex) {
		var source = placeholder.substring(0, lastColonIndex);
		var listPrefix = LIST_PLACEHOLDER + COLON;
		if (source.startsWith(listPrefix)) {
			return source.substring(listPrefix.length());
		}
		return source;
	}

	/**
	 * Get properties from IDM result based on placeholder.
	 * Example placeholder formats:
	 * - PROPS:propertyName
	 * - LIST:PROPS:propertyName
	 *
	 * @param placeholder Placeholder string
	 * @param result Current IDM result
	 * @param undefinedValue Value to use when property is not found
	 * @return List of resolved property values
	 */
	public static List<String> getProperties(String placeholder, IdmResult result, String undefinedValue) {
		final var lastColonIndex = placeholder.lastIndexOf(COLON);
		final var claimName = placeholder.substring(lastColonIndex + 1);

		if (result == null || result.getProperties() == null || result.getProperties().isEmpty()) {
			return List.of(undefinedValue);
		}

		List<String> values = new ArrayList<>();
		result.getProperties().forEach((key, value) -> {
			if (key != null && (claimName.equals(key.getName()) || claimName.equals(key.getNamespaceUri()))) {
				values.addAll(value);
			}
		});

		if (values.isEmpty()) {
			return List.of(undefinedValue);
		}
		return values.stream().distinct().map(value -> value != null ? value : undefinedValue).toList();
	}
}
