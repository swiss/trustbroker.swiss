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

package swiss.trustbroker.common.dto;


import lombok.Getter;

/**
 * The format of the <code>AcceptedUrl</code>.
 */
@Getter
public enum AcceptedUrlFormat {
	/**
	 * Legacy implementation that supports URL match and limited regular expression matching.
	 * <ol>
	 *     <li>Literal matching</li>
	 *     <li>An explicit default port is matched (e.g. <code>https://host:443</code>)</li>
	 * 	   <li><code>/.*</code> postfix in path where trailing slash is optional</li>
	 * 	   <li>Regular expression matching as long as the full expression is a valid absolute URI, e.g. <code>.* within
	 * 	   the path</code>.</li>
	 * </ol>
	 * This will be removed in a future release as there is no means of distinguishing whether e.g. a dot in the config
	 * should be interpreted as a regular expression wildcard or just a dot in a normal URL.
	 */
	ANY,

	/**
	 * Full URL that matches an identical input only.
	 * <br/>
	 * Default port matching is supported.
	 */
	FULL,

	/**
	 * URL prefix.
	 * <br/>
	 * The value matches:
	 * <ol>
	 *     <li>An identical input like <code>FULL</code>. I.e. <code>/path/sub</code> matches <code>/path/sub</code>.</li>
	 *     <li>An URL that starts with this entry with a trailing slash added if missing. I.e. both <code>/path/sub</code>
	 *     and <code>/path/sub</code> match all of <code>/path/sub</code>, <code>/path/sub/</code>,
	 *     <code>/path/sub/other</code>, but not <code>/path/sub2</code></li>
	 *     <li>Default port matching is supported.</li>
	 * </ol>
	 */
	PREFIX,

	/**
	 * Regular expression matching the full URL.
	 * <br/>
	 * The expression does not have to be a valid URI. This option not support default port matching - you have to handle
	 * them in the regular expression if needed.
	 * <br/>
	 * E.g. <code>http://host/path/.*</code> matches <code>http://host/path/sub</code> but not <code>http://host/path</code>.
	 * The latter would be matched by <code>http://host/path(/.*)?</code>.
	 */
	REGEX,

	/**
	 * Regular expression matching for the path only while applying host/port matching normally.
	 * <br/>
	 * Default port matching is supported.
	 * This will only work if the full pattern is a valid URI that can be parsed into URI components.
	 * E.g. <code>.*</code> or <code>.</code> work, but <code>?</code> does not work as it starts the query string.
	 * <br/>
	 * E.g. <code>http://host/path/.*</code> matches <code>http://host/path/sub</code> but not <code>http://host/path</code>.
	 */
	PATH_REGEX,

	/**
	 * Set internally for entries that cannot be used due to invalid URLs.
	 */
	IGNORED
}
