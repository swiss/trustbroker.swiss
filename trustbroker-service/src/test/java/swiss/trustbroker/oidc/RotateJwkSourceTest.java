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

package swiss.trustbroker.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.dto.JwkCacheEntity;
import swiss.trustbroker.sessioncache.service.JwkCacheService;

class RotateJwkSourceTest {

	@Mock
	private JwkCacheService jwkCacheService;

	@Mock
	private MetricsService metricsService;

	private RotateJwkSource<SecurityContext> rotateJwkSource;

	private AutoCloseable mocks;

	@BeforeEach
	void setUp() {
		mocks = MockitoAnnotations.openMocks(this);
		rotateJwkSource = new RotateJwkSource<>(jwkCacheService, metricsService);
	}

	@AfterEach
	void tearDown() throws Exception {
		mocks.close();
	}

	@ParameterizedTest
	@MethodSource
	void getTest(String scenario, List<JwkCacheEntity> entities, boolean shouldCreateNew, int expectedCount) throws Exception {
		var selector = new JWKSelector(new JWKMatcher.Builder().build());

		doReturn(entities).when(jwkCacheService).getJWTEntities();

		if (shouldCreateNew) {
			var newJwk = generateJwk("new-key");
			doReturn(newJwk).when(jwkCacheService).createJWK();
		}

		var result = rotateJwkSource.get(selector, null);

		assertEquals(expectedCount, result.size());
		verify(metricsService).gauge(anyString(), anyLong());

		if (shouldCreateNew) {
			verify(jwkCacheService).createJWK();
			verify(jwkCacheService).saveJWK(any());
		} else {
			verify(jwkCacheService, never()).createJWK();
		}
	}

	static Stream<Arguments> getTest() throws JOSEException {
		var validKey = createEntity("valid-key", Instant.now().plus(1, ChronoUnit.HOURS));
		var expiredKey = createEntity("expired-key", Instant.now().minus(1, ChronoUnit.HOURS));

		return Stream.of(
				// Empty cache → creates new JWK
				Arguments.of("empty cache", Collections.emptyList(), true, 1),
				// All keys expired → creates new JWK
				Arguments.of("all expired", List.of(expiredKey), true, 1),
				// Has valid keys → returns them via selector
				Arguments.of("has valid keys", List.of(validKey), false, 1),
				// Mix of valid and expired → returns only valid
				Arguments.of("mixed valid/expired", List.of(validKey, expiredKey), false, 1)
		);
	}

	@ParameterizedTest
	@MethodSource
	void getWithContextThrowsExceptionTest(SecurityContext context) {
		var selector = new JWKSelector(new JWKMatcher.Builder().build());

		var exception = assertThrows(TechnicalException.class,
				() -> rotateJwkSource.get(selector, context));

		assertFalse(exception.getMessage().isEmpty());
	}

	static Stream<Arguments> getWithContextThrowsExceptionTest() {
		return Stream.of(
				// Non-null context → throws TechnicalException
				Arguments.of(new TestSecurityContext())
		);
	}

	private static JwkCacheEntity createEntity(String keyId, Instant expiration) throws JOSEException {
		var entity = new JwkCacheEntity();
		entity.setId(keyId);
		entity.setJwk(generateJwk(keyId).toJSONString());
		entity.setExpirationTimestamp(Timestamp.from(expiration));
		return entity;
	}

	private static JWK generateJwk(String keyId) throws JOSEException {
		return new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS)
				.keyID(keyId)
				.generate();
	}

	private static class TestSecurityContext implements SecurityContext {
	}
}

