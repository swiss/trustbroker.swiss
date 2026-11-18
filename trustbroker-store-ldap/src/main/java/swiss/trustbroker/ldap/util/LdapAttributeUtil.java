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

package swiss.trustbroker.ldap.util;

import java.util.Base64;

import lombok.extern.slf4j.Slf4j;

/**
 * Converts LDAP attributes to XML-safe strings.
 * <p>
 * Supported binary representations:
 * <ul>
 *     <li>{@code objectSid} and every {@code tokenGroups} value: MS-DTYP SID string</li>
 *     <li>{@code objectGUID}: Microsoft GUID string (mixed-endian binary layout)</li>
 *     <li>{@code userCertificate} and any other value received as {@code byte[]}: Base64</li>
 * </ul>
 * Limitations: textual SID/GUID values are kept as text and are not validated; attributes not configured as binary in
 * JNDI may already be irreversibly decoded before reaching this utility; certificates are not parsed or converted to PEM;
 * malformed known binary values fall back to Base64; SID revision 1 and the Windows limit of 15 sub-authorities are not
 * enforced. For compatibility with common LDAP SID decoders, trailing bytes after the counted SID sub-authorities are
 * ignored.
 */
@Slf4j
public final class LdapAttributeUtil {

	private static final String OBJECT_SID = "objectSid";
	private static final String OBJECT_GUID = "objectGUID";
	private static final String TOKEN_GROUPS = "tokenGroups";
	private static final String USER_CERTIFICATE = "userCertificate";

	/** Attributes that JNDI must return as byte[] (java.naming.ldap.attributes.binary, space separated). */
	public static final String BINARY_ATTRIBUTES = String.join(" ", OBJECT_SID, OBJECT_GUID, TOKEN_GROUPS, USER_CERTIFICATE);

	private LdapAttributeUtil() {
	}

	/**
	 * Binary values are converted by attribute type (objectSid/tokenGroups to SID, objectGUID to GUID,
	 * any other byte[] such as userCertificate to Base64). Text values have XML-invalid characters removed.
	 */
	public static String toXmlSafeString(String id, Object value) {
		if (value == null) {
			return null;
		}
		if (value instanceof byte[] bytes) {
			return toBinaryString(id, bytes);
		}
		var text = value.toString();
		var safe = removeInvalidXmlChars(text);
		if (!safe.equals(text)) {
			log.warn("Removed invalid XML characters from LDAP attribute {}", id);
		}
		return safe;
	}

	static String toBinaryString(String id, byte[] bytes) {
		try {
			if (OBJECT_SID.equalsIgnoreCase(id) || TOKEN_GROUPS.equalsIgnoreCase(id)) {
				return toSidString(bytes);
			}
			if (OBJECT_GUID.equalsIgnoreCase(id)) {
				return toGuidString(bytes);
			}
		}
		catch (IllegalArgumentException e) {
			log.warn("Invalid binary value for LDAP attribute {}, using Base64: {}", id, e.getMessage());
		}
		return Base64.getEncoder().encodeToString(bytes);
	}

	/**
	 * Converts the binary SID structure (MS-DTYP 2.4.2) into its string form, e.g. S-1-5-21-...
	 */
	static String toSidString(byte[] sid) {
		if (sid.length < 8) {
			throw new IllegalArgumentException("Invalid SID length: " + sid.length);
		}
		int revision = sid[0] & 0xFF;
		int subAuthorityCount = sid[1] & 0xFF;
		// like the common decodeSID implementation, only the counted sub-authorities are read, trailing bytes are ignored
		if (sid.length < 8 + 4 * subAuthorityCount) {
			throw new IllegalArgumentException("Invalid SID length " + sid.length + " for sub-authority count " + subAuthorityCount);
		}
		// 48-bit big-endian identifier authority
		long authority = 0;
		for (int i = 2; i <= 7; i++) {
			authority = (authority << 8) | (sid[i] & 0xFF);
		}
		var builder = new StringBuilder("S-").append(revision).append('-');
		// MS-DTYP: decimal below 2^32, hex (0x...) otherwise
		if (authority < 4294967296L) {
			builder.append(authority);
		}
		else {
			builder.append("0x").append(Long.toHexString(authority).toUpperCase());
		}
		// sub-authorities are 32-bit little-endian, unsigned
		for (int i = 0; i < subAuthorityCount; i++) {
			int offset = 8 + 4 * i;
			long subAuthority = (sid[offset] & 0xFFL)
					| ((sid[offset + 1] & 0xFFL) << 8)
					| ((sid[offset + 2] & 0xFFL) << 16)
					| ((sid[offset + 3] & 0xFFL) << 24);
			builder.append('-').append(subAuthority);
		}
		return builder.toString();
	}

	/**
	 * Converts the 16-byte objectGUID (first three fields little-endian) into the standard 8-4-4-4-12 form.
	 */
	static String toGuidString(byte[] guid) {
		if (guid.length != 16) {
			throw new IllegalArgumentException("Invalid GUID length: " + guid.length);
		}
		return hex(guid, 3, 0) + "-" + hex(guid, 5, 4) + "-" + hex(guid, 7, 6) + "-" + hex(guid, 8, 9) + "-" + hex(guid, 10, 15);
	}

	/** Hex of the bytes from index 'from' to 'to' (inclusive), walking backwards when from > to. */
	private static String hex(byte[] bytes, int from, int to) {
		var builder = new StringBuilder();
		int step = from <= to ? 1 : -1;
		for (int i = from; ; i += step) {
			builder.append(String.format("%02x", bytes[i] & 0xFF));
			if (i == to) {
				break;
			}
		}
		return builder.toString();
	}

	static String removeInvalidXmlChars(String text) {
		var builder = new StringBuilder(text.length());
		text.codePoints()
				.filter(LdapAttributeUtil::isValidXmlChar)
				.forEach(builder::appendCodePoint);
		return builder.toString();
	}

	private static boolean isValidXmlChar(int cp) {
		return cp == 0x9 || cp == 0xA || cp == 0xD
				|| (cp >= 0x20 && cp <= 0xD7FF)
				|| (cp >= 0xE000 && cp <= 0xFFFD)
				|| (cp >= 0x10000 && cp <= 0x10FFFF);
	}
}

