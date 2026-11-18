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

package swiss.trustbroker.ldap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.util.Map;

import org.apache.commons.pool2.impl.GenericKeyedObjectPool;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.ldap.pool2.factory.PooledContextSource;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapServiceEndpointConfig;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.metrics.service.MetricsService;

/**
 * The pooled context sources are created inside the lazy supplier and are not managed beans, so they must be closed
 * explicitly on shutdown. Otherwise the commons-pool evictor thread survives the application context.
 */
class LdapContextSourceRegistryTest {

	@Test
	void destroyClosesPoolsCreatedByLazySupplier() throws Exception {
		var config = new MultiLdapConfig();
		var registry = config.ldapContextSourceRegistry();
		var templates = config.ldapTemplates(createPropertiesWithStore("LDAP", "ldap://localhost:389"),
				emptyMetricsProvider(), registry);

		var contextSource = templates.get("LDAP").get().getContextSource();
		assertInstanceOf(PooledContextSource.class, contextSource);
		var pool = keyedObjectPool((PooledContextSource) contextSource);
		assertFalse(pool.isClosed(), "pool must be running before shutdown");

		registry.destroy();

		assertTrue(pool.isClosed(), "pool must be closed on application context shutdown");
	}

	@Test
	void poolCreatedAfterShutdownIsClosedImmediately() throws Exception {
		var config = new MultiLdapConfig();
		var registry = config.ldapContextSourceRegistry();
		var templates = config.ldapTemplates(createPropertiesWithStore("LDAP", "ldap://localhost:389"),
				emptyMetricsProvider(), registry);

		// shutdown happens before the store was ever used
		registry.destroy();

		var contextSource = templates.get("LDAP").get().getContextSource();
		var pool = keyedObjectPool((PooledContextSource) contextSource);

		assertTrue(pool.isClosed(), "pool created after shutdown must not stay alive");
	}

	@Test
	void destroyIsIdempotent() {
		var config = new MultiLdapConfig();
		var registry = config.ldapContextSourceRegistry();
		config.ldapTemplates(createPropertiesWithStore("LDAP", "ldap://localhost:389"), emptyMetricsProvider(), registry)
				.get("LDAP").get();

		registry.destroy();
		registry.destroy();
	}

	private static GenericKeyedObjectPool<Object, Object> keyedObjectPool(PooledContextSource pooledContextSource)
			throws Exception {
		var field = PooledContextSource.class.getDeclaredField("keyedObjectPool");
		field.setAccessible(true);
		@SuppressWarnings("unchecked")
		var pool = (GenericKeyedObjectPool<Object, Object>) field.get(pooledContextSource);
		return pool;
	}

	private static ObjectProvider<MetricsService> emptyMetricsProvider() {
		@SuppressWarnings("unchecked")
		ObjectProvider<MetricsService> metricsServiceProvider = mock(ObjectProvider.class);
		doReturn(null).when(metricsServiceProvider).getIfAvailable();
		return metricsServiceProvider;
	}

	private static TrustBrokerProperties createPropertiesWithStore(String storeName, String ldapUrl) {
		var endpoint = new LdapServiceEndpointConfig();
		endpoint.setUrl(ldapUrl);
		endpoint.getAuthentication().setUsername("cn=admin,dc=example,dc=org");
		endpoint.getAuthentication().setPassword("secret");
		var ldapConfig = new LdapStoreConfig(true, Map.of(storeName, endpoint), "UNDEF", ":");
		var properties = new TrustBrokerProperties();
		properties.setLdap(ldapConfig);
		return properties;
	}

}

