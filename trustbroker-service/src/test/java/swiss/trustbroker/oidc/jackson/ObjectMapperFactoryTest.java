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

package swiss.trustbroker.oidc.jackson;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import tools.jackson.databind.exc.InvalidTypeIdException;

class ObjectMapperFactoryTest {

	public static class TestClass implements Comparable<TestClass> {
		// just instantiation

		@Override
		public int compareTo(TestClass o) {
			return Integer.compare(hashCode(), o.hashCode());
		}
	}

	@Test
	void testSimpleSaveLoad() {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var expected = "TEST";
		var encoded = mapper.writeValueAsString(expected);
		var decoded = mapper.readValue(encoded, expected.getClass());
		assertThat(decoded, equalTo(expected));
	}

	@Test
	void testAcceptableDataSaveLoad() {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var claims = new HashMap<String, List<Object>>();
		claims.put("emptyArrayList", new ArrayList<>());
		claims.put("emptyList", Collections.emptyList());
		claims.put("unmodifiableList", Collections.unmodifiableList(new ArrayList<>()));
		claims.put("immutableList", List.of("TEST1"));
		claims.put("epocTime", List.of(Long.MIN_VALUE));
		// basic JDK types that might be used:
		claims.put("bool", List.of(Boolean.TRUE));
		claims.put("int", List.of(Integer.MIN_VALUE));
		claims.put("emptyMap", List.of(Collections.emptyMap()));
		claims.put("immutableMap", List.of(Map.of("key", "value")));
		var encoded = mapper.writeValueAsString(claims);
		var decoded = mapper.readValue(encoded, claims.getClass());
		assertThat(decoded.size(), equalTo(claims.size()));
	}

	@Test
	void testSaml2Principal() {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var attrs = new HashMap<String, List<Object>>();
		var vals = new ArrayList<>();
		vals.add("VAL1");
		vals.add("VAL2");
		attrs.put("multiValued", vals);
		var principal = new DefaultSaml2AuthenticatedPrincipal("TEST", attrs);
		var encoded = mapper.writeValueAsString(principal);
		var decoded = mapper.readValue(encoded, principal.getClass());
		assertThat(decoded.getAttributes().size(), equalTo(attrs.size()));
	}

	@ParameterizedTest
	@MethodSource
	void testBlocking(Object writeObject, Object readObject) {
		var mapper = ObjectMapperFactory.springSecObjectMapper();
		var encoded = mapper.writeValueAsString(writeObject);
		if (readObject == null) {
			assertThrows(InvalidTypeIdException.class, () ->
				mapper.readValue(encoded, writeObject.getClass())
			);
		}
		else {
			var decoded = mapper.readValue(encoded, writeObject.getClass());
			assertThat(decoded, equalTo(readObject));
		}
	}

	// Collections.unmodifiableCollection -> Cannot construct instance of `java.util.Collections$UnmodifiableCollection
	// Collections.unmodifiableSet => Unexpected token (`JsonToken.END_ARRAY`), expected `JsonToken.VALUE_STRING`: need String, Number of Boolean value that contains type id (for subtype of java.lang.Object)
	static Object[][] testBlocking() {
		return new Object[][] {
				{ new TestClass(), null },
				{ Collections.unmodifiableMap(new HashMap<String, String>()),
						Map.of("@class", "java.util.Collections$UnmodifiableMap") },
				{ new LinkedHashMap<String, String>(), new LinkedHashMap<String, String>() },
				{ new TreeMap<String, String>(), new TreeMap<String, String>() },
				{ List.of("allowed"), List.of("allowed") },
				{ Map.of("key", "allowed"), Map.of("key", "allowed") }
		};
	}
}
