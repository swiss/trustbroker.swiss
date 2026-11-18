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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class LdapAttributeUtilTest {

	@Test
	void binaryAttributeConfigurationContainsMicrosoftAdAttributes() {
		assertThat(LdapAttributeUtil.BINARY_ATTRIBUTES.split(" "))
				.containsExactly("objectSid", "objectGUID", "tokenGroups", "userCertificate");
	}

	@ParameterizedTest(name = "{0} converts to {2}")
	@CsvSource({
			"objectSid, AQUAAAAAAAUVAAAAx/f+13x3VciUWs4B9QMAAA==, S-1-5-21-3623811015-3361044348-30300820-1013",
			"tokenGroups, AQUAAAAAAAUVAAAAx/f+13x3VciUWs4BAQIAAA==, S-1-5-21-3623811015-3361044348-30300820-513",
			"objectSid, AQUAAAAAAAUVAAAA6AMAANAHAAC4CwAAGQAAAEEZQg==, S-1-5-21-1000-2000-3000-25"
	})
	void convertsSidBinaryAttributes(String attribute, String base64, String expected) {
		assertThat(LdapAttributeUtil.toBinaryString(attribute, Base64.getDecoder().decode(base64)))
				.isEqualTo(expected);
	}

	@ParameterizedTest(name = "{0} converts to {1}")
	@CsvSource({
			"AQEAAP////8BAAAA, S-1-4294967295-1",
			"AQEAAQAAAAABAAAA, S-1-0x100000000-1"
	})
	void formatsSidAuthorityAccordingToMsDtyp(String base64, String expected) {
		assertThat(LdapAttributeUtil.toSidString(Base64.getDecoder().decode(base64))).isEqualTo(expected);
	}

	@Test
	void convertsMicrosoftMixedEndianObjectGuid() {
		var guid = Base64.getDecoder().decode("4AQlP4lP0xGaDAMF6CwzAQ==");

		assertThat(LdapAttributeUtil.toBinaryString("objectGUID", guid))
				.isEqualTo("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
	}

	@ParameterizedTest(name = "{0} uses Base64 fallback")
	@CsvSource({
			"userCertificate, MIIBAg==",
			"customBinary, MIIBAg==",
			"objectSid, AQEA",
			"objectGUID, AQID"
	})
	void encodesOpaqueOrMalformedBinaryValueAsBase64(String attribute, String base64) {
		assertThat(LdapAttributeUtil.toBinaryString(attribute, Base64.getDecoder().decode(base64)))
				.isEqualTo(base64);
	}

	@Test
	void removesOnlyCharactersForbiddenByXml10FromText() {
		assertThat(LdapAttributeUtil.toXmlSafeString("description", "A\u0000B\u0019C\t\n\rD\uD83D\uDE00"))
				.isEqualTo("ABC\t\n\rD\uD83D\uDE00");
	}

	@ParameterizedTest(name = "{0} is preserved")
	@CsvSource(value = {
			"Müller|Müller",
			"Tűrő|Tűrő",
			"Anne-Marie O'Connor|Anne-Marie O'Connor"
	}, delimiter = '|')
	void preservesTypicalUserNames(String input, String expected) {
		assertThat(LdapAttributeUtil.toXmlSafeString("cn", input)).isEqualTo(expected);
	}

	@Test
	void textualSidIsKeptAsTextAndNotParsed() {
		// Textual SID/GUID validation is intentionally outside this binary conversion utility's scope.
		assertThat(LdapAttributeUtil.toXmlSafeString("objectSid", "S-not-validated"))
				.isEqualTo("S-not-validated");
	}

}
