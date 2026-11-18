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

package swiss.trustbroker.federation.xmlconfig;

/**
 * Format of a @Default annotation
 */
public enum DefaultFormat {
	/**
	 * Value that is used as-is.
	 * <br/>
	 * Conversion of value to boolean/int/long/enum is supported. Fallback is not used.
	 */
	VALUE,

	/**
	 * Value is the name of a property that will be resolved from the Spring configuration.
	 * <br/>
	 * Conversion of value to boolean/int/long/enum is supported. Fallback is used if the resolution returns null.
	 * Implementation note: Spring Environment is used for the lookup, this property defaults in the code are not considered,
	 * hence the fallback, we might switch to using reflection.
	 * <br/>
	 * E.g. <code>trustbroker.config.attribute</code>.
	 */
	PROPERTY,

	/**
	 * Value is using Spring EL (expression language).
	 * <br/>
	 * Placeholders in the form <code>${trustbroker.config.attribute}</code> are resolved before evaluation. Fallback is not used.
	 * <br/>
	 * Note that if you just have a placeholder, depending on the type you may need single quotes around the placeholder,
	 * i.e. <code>'${trustbroker.config.attribute}'</code> (for Enum, String) - better use PROPERTY instead in this case.
	 */
	EXPRESSION;
}
