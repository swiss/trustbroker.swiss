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

package swiss.trustbroker.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.TestPropertySource;
import swiss.trustbroker.federation.xmlconfig.Default;
import swiss.trustbroker.federation.xmlconfig.DefaultFormat;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;

@SpringBootTest(classes = DefaultHandler.class)
@TestPropertySource(properties = { "config.string=config-value", "config.enum=INVALID", "config.int=123", "config.bool=true" })
class DefaultHandlerTest {

	// helper class to instantiate @Default - the field value is the expected evaluated result
	@SuppressWarnings("unused")
	private static class EvaluateFixture {

		@Default("default-string")
		private final String valueString = "default-string";

		@Default("true")
		private final Boolean valueBool = true;

		@Default("42")
		private final Integer valueInt = 42;

		@Default("1024")
		private final Long valueLong = 1024L;

		@Default("INVALID")
		private final FeatureEnum valueEnum = FeatureEnum.INVALID;

		@Default(value = "config.int", format = DefaultFormat.PROPERTY)
		private final Integer referenceInt = 123;

		@Default(value = "config.bool", format = DefaultFormat.PROPERTY)
		private final Boolean referenceBool = true;

		@Default(value = "config.enum", format = DefaultFormat.PROPERTY)
		private final FeatureEnum referenceEnum = FeatureEnum.INVALID;

		@Default(value = "config.enum.unknown", format = DefaultFormat.PROPERTY, fallback = "INVALID")
		private final FeatureEnum referenceUnknown = FeatureEnum.INVALID;

		@Default(value = "1 + 2", format = DefaultFormat.EXPRESSION)
		private final Integer expressionInt = 3;

		@Default(value = "'${config.enum}'", format = DefaultFormat.EXPRESSION)
		private final FeatureEnum expressionEnum = FeatureEnum.INVALID;

		@Default(value = "'${config.string}-extended'", format = DefaultFormat.EXPRESSION)
		private final String expressionWithReference = "config-value-extended";

		@Default

		private final String emptyValues = "";
	}

	@Autowired
	private Environment environment;

	@Autowired
	private DefaultHandler defaultHandler;

	@ParameterizedTest
	@MethodSource
	void evaluate(Default def, Class<?> targetClass, Object expectedValue) {
		assertEquals(expectedValue, defaultHandler.evaluate(def, targetClass));
	}

	private static Object[][] evaluate() throws Exception {
		return new Object[][] {
				evaluateParamsForField("valueString"),
				evaluateParamsForField("valueInt"),
				evaluateParamsForField("valueLong"),
				evaluateParamsForField("valueBool"),
				evaluateParamsForField("valueEnum"),
				evaluateParamsForField("referenceInt"),
				evaluateParamsForField("referenceBool"),
				evaluateParamsForField("referenceEnum"),
				evaluateParamsForField("referenceUnknown"),
				evaluateParamsForField("expressionInt"),
				evaluateParamsForField("expressionEnum"),
				evaluateParamsForField("expressionWithReference"),
				evaluateParamsForField("emptyValues")
		};
	}

	private static Object[] evaluateParamsForField(String fieldName) throws Exception {
		var fixture = new EvaluateFixture();
		var field = EvaluateFixture.class.getDeclaredField(fieldName);
		return new Object[] { field.getAnnotation(Default.class), field.getType(), field.get(fixture) };
	}

	@Test
	void applyDefaultValuesSecurityPolicies() {
		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .build();
		assertNull(rpObject.getSecurityPolicies().getRequireSignedAuthnRequest());
		assertNull(rpObject.getSecurityPolicies().getRequireSignedLogoutNotificationRequest());
		assertNull(rpObject.getSecurityPolicies().getRequireEncryptedAssertion());
		assertNull(rpObject.getSecurityPolicies().getValidateXmlSchema());
		assertNull(rpObject.getSecurityPolicies().getNotOnOrAfterSeconds());

		defaultHandler.applyDefaultValues(rpObject);

		assertTrue(rpObject.getSecurityPolicies().getRequireSignedAuthnRequest());
		assertTrue(rpObject.getSecurityPolicies().getRequireSignedLogoutNotificationRequest());
		assertTrue(rpObject.getSecurityPolicies().getRequireEncryptedAssertion());
		assertTrue(rpObject.getSecurityPolicies().getValidateXmlSchema());
		assertEquals(3600, rpObject.getSecurityPolicies().getNotOnOrAfterSeconds());
	}

	@Test
	void applyDefaultValuesOidcSecurityPolicies() {
		OidcClient client = OidcClient.builder().build();
		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .oidc(Oidc.builder()
		                                              .clients(List.of(client))
		                                              .build())
		                                    .build();

		assertNull(client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertNull(client.getOidcSecurityPolicies().getEncryptionMethod());
		assertNull(client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertNull(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());

		defaultHandler.applyDefaultValues(rpObject);

		assertEquals(JWEAlgorithm.RSA_OAEP_256.getName(), client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertEquals(EncryptionMethod.A256GCM.getName(), client.getOidcSecurityPolicies().getEncryptionMethod());
		assertEquals(1, client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertFalse(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertEquals(60, client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertEquals(1, client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertEquals(60, client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertEquals(3600, client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());
	}

	@Test
	void applyDefaultValuesOidcSecurityPoliciesIfNotSet() {
		String alg = JWEAlgorithm.ECDH_ES_A128KW.getName();
		OidcClient client = OidcClient.builder()
		                              .oidcSecurityPolicies(
											  OidcSecurityPolicies.builder()
											                      .allowPublicClientTokenExchange(true)
											                      .encryptionAlgorithm(alg)
											                      .build())
		                              .build();
		RelyingParty rpObject = RelyingParty.builder()
		                                    .securityPolicies(SecurityPolicies.builder()
		                                                                      .build())
		                                    .oidc(Oidc.builder()
		                                              .clients(List.of(client))
		                                              .build())
		                                    .build();

		assertNotNull(client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertNull(client.getOidcSecurityPolicies().getEncryptionMethod());
		assertNull(client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertNotNull(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertNull(client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());

		defaultHandler.applyDefaultValues(rpObject);

		assertEquals(alg, client.getOidcSecurityPolicies().getEncryptionAlgorithm());
		assertEquals(EncryptionMethod.A256GCM.getName(), client.getOidcSecurityPolicies().getEncryptionMethod());
		assertEquals(1, client.getOidcSecurityPolicies().getSessionTimeToLiveMin());
		assertTrue(client.getOidcSecurityPolicies().getAllowPublicClientTokenExchange());
		assertEquals(60, client.getOidcSecurityPolicies().getSubjectTokenMaxAgeSec());
		assertEquals(1, client.getOidcSecurityPolicies().getSubjectTokenMaxUseCount());
		assertEquals(60, client.getOidcSecurityPolicies().getClientAssertionMaxAgeSec());
		assertEquals(3600, client.getOidcSecurityPolicies().getClientAssertionExpirationLifeTimeSec());
	}
}
