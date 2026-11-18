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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.function.Supplier;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool2.factory.PooledContextSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapServiceEndpointConfig;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.metrics.service.MetricsService;

class MultiLdapConfigTest {

	@Test
	void ldapTemplatesInitializesOnFirstUseAndRecordsTimer() {
		var meterRegistry = new SimpleMeterRegistry();
		var metricsService = new MetricsService(meterRegistry);
		@SuppressWarnings("unchecked")
		ObjectProvider<MetricsService> metricsServiceProvider = mock(ObjectProvider.class);
		doReturn(metricsService).when(metricsServiceProvider).getIfAvailable();
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, metricsServiceProvider, config.ldapContextSourceRegistry());

		assertEquals(1, templates.size());
		assertNull(meterRegistry.find("trustbroker.ldap.store.init").timer());

		var supplier = templates.get("LDAP");
		assertNotNull(supplier);
		var firstTemplate = supplier.get();
		var secondTemplate = supplier.get();

		assertSame(firstTemplate, secondTemplate);
		var timer = meterRegistry.find("trustbroker.ldap.store.init").tag("store", "LDAP").timer();
		assertNotNull(timer);
		assertEquals(1, timer.count());
	}

	@Test
	void ldapTemplatesFailedInitIncrementsFailureCounter() {
		var meterRegistry = new SimpleMeterRegistry();
		var metricsService = new MetricsService(meterRegistry);
		@SuppressWarnings("unchecked")
		ObjectProvider<MetricsService> metricsServiceProvider = mock(ObjectProvider.class);
		doReturn(metricsService).when(metricsServiceProvider).getIfAvailable();
		var trustBrokerProperties = createPropertiesWithStore("BROKEN", "http://localhost:389");

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, metricsServiceProvider, config.ldapContextSourceRegistry());

		var supplier = templates.get("BROKEN");
		assertNotNull(supplier);
		assertThrows(TechnicalException.class, supplier::get);

		var counter = meterRegistry.find("trustbroker.ldap.store.init.failures").tag("store", "BROKEN").counter();
		assertNotNull(counter);
		assertEquals(1.0d, counter.count());
	}

	@Test
	void ldapTemplatesUsePooledContextSourceByDefault() {
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, emptyMetricsProvider(), config.ldapContextSourceRegistry());

		var template = templates.get("LDAP").get();
		assertInstanceOf(PooledContextSource.class, template.getContextSource());
	}

	@Test
	void ldapTemplatesUsePlainContextSourceWhenPoolingDisabled() {
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");
		trustBrokerProperties.getLdap().getStores().get("LDAP").getPool().setEnabled(false);

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, emptyMetricsProvider(), config.ldapContextSourceRegistry());

		var template = templates.get("LDAP").get();
		assertInstanceOf(LdapContextSource.class, template.getContextSource());
	}

	@Test
	void ldapTemplatesConvertPoolTimeoutsFromSecondsToMilliseconds() {
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");
		var pool = trustBrokerProperties.getLdap().getStores().get("LDAP").getPool();
		pool.setMaxWaitSec(7);
		pool.setTimeBetweenEvictionRunsSec(11);
		pool.setMinEvictableIdleTimeSec(13);

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, emptyMetricsProvider(), config.ldapContextSourceRegistry());

		var template = templates.get("LDAP").get();
		assertInstanceOf(PooledContextSource.class, template.getContextSource());

		var pooledContextSource = (PooledContextSource) template.getContextSource();
		var poolConfig = pooledContextSource.getPoolConfig();
		assertEquals(7000L, poolConfig.getMaxWaitMillis());
		assertEquals(11000L, poolConfig.getTimeBetweenEvictionRunsMillis());
		assertEquals(13000L, poolConfig.getMinEvictableIdleTimeMillis());
	}

	@Test
	void ldapTemplatesUseTimeoutsFromEndpointNetworkConfig() throws Exception {
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");
		var network = trustBrokerProperties.getLdap().getStores().get("LDAP").getNetwork();
		network.setBackendConnectTimeoutSec(7);
		network.setBackendResponseTimeoutSec(17);

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, emptyMetricsProvider(), config.ldapContextSourceRegistry());

		var template = templates.get("LDAP").get();
		var pooledContextSource = (PooledContextSource) template.getContextSource();
		var contextSource = pooledContextSource.getContextSource();
		assertInstanceOf(LdapContextSource.class, contextSource);
		var env = getAnonymousEnv(contextSource);

		assertEquals("7000", env.get("com.sun.jndi.ldap.connect.timeout"));
		assertEquals("17000", env.get("com.sun.jndi.ldap.read.timeout"));
	}

	@Test
	void ldapTemplatesUseNetworkDefaultTimeoutsWhenNotConfigured() throws Exception {
		var trustBrokerProperties = createPropertiesWithStore("LDAP", "ldap://localhost:389");

		var config = new MultiLdapConfig();
		Map<String, Supplier<LdapTemplate>> templates = config.ldapTemplates(trustBrokerProperties, emptyMetricsProvider(), config.ldapContextSourceRegistry());

		var template = templates.get("LDAP").get();
		var pooledContextSource = (PooledContextSource) template.getContextSource();
		var env = getAnonymousEnv(pooledContextSource.getContextSource());

		assertEquals("30000", env.get("com.sun.jndi.ldap.connect.timeout"));
		assertEquals("30000", env.get("com.sun.jndi.ldap.read.timeout"));
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

	@SuppressWarnings("unchecked")
	private static Map<String, Object> getAnonymousEnv(Object contextSource) throws Exception {
		Method method = contextSource.getClass().getSuperclass().getDeclaredMethod("getAnonymousEnv");
		method.setAccessible(true);
		return (Map<String, Object>) method.invoke(contextSource);
	}

}

