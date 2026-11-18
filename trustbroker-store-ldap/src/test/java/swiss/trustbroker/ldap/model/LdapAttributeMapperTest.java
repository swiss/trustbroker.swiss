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

package swiss.trustbroker.ldap.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.ldap.core.DirContextAdapter;

class LdapAttributeMapperTest {

	private final LdapAttributeMapper mapper = new LdapAttributeMapper();

	@Test
	void mapsSingleValuedAttributes() throws Exception {
		var context = new DirContextAdapter();
		context.setAttributeValue("cn", "Müller");
		context.setAttributeValue("description", "A\u0000B");

		var result = mapper.mapFromContext(context);

		assertThat(result)
				.containsEntry("cn", List.of("Müller"))
				.containsEntry("description", List.of("AB"));
	}

	@Test
	void mapsAllValuesOfMultiValuedAttributes() throws Exception {
		var context = new DirContextAdapter();
		context.setAttributeValues("memberOf", new String[] {
				"cn=group-1,ou=groups,dc=example,dc=org",
				"cn=group-2,ou=groups,dc=example,dc=org",
				"cn=group-3,ou=groups,dc=example,dc=org"
		});

		var result = mapper.mapFromContext(context);

		assertThat(result)
				.containsEntry("memberOf", List.of(
						"cn=group-1,ou=groups,dc=example,dc=org",
						"cn=group-2,ou=groups,dc=example,dc=org",
						"cn=group-3,ou=groups,dc=example,dc=org"));
	}
}

