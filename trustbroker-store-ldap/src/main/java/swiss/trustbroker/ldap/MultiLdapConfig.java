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

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool2.factory.PoolConfig;
import org.springframework.ldap.pool2.factory.PooledContextSource;
import org.springframework.ldap.pool2.validation.DefaultDirContextValidator;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapServiceEndpointConfig;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.ldap.util.LdapAttributeUtil;
import swiss.trustbroker.metrics.service.MetricsService;

@Configuration
@ConditionalOnBooleanProperty("trustbroker.config.ldap.enabled")
@Slf4j
public class MultiLdapConfig {

	/**
	 * Managed bean owning the lifecycle of the pooled context sources created lazily per store.
	 */
	@Bean
	public LdapContextSourceRegistry ldapContextSourceRegistry() {
		return new LdapContextSourceRegistry();
	}

	@Bean
	public Map<String, Supplier<LdapTemplate>> ldapTemplates(TrustBrokerProperties trustBrokerProperties,
			ObjectProvider<MetricsService> metricsServiceProvider, LdapContextSourceRegistry ldapContextSourceRegistry) {
		Map<String, Supplier<LdapTemplate>> templates = new LinkedHashMap<>();
		var metricsService = metricsServiceProvider.getIfAvailable();

		LdapStoreConfig ldap = trustBrokerProperties.getLdap();
		if (ldap.getStores() == null || ldap.getStores().isEmpty()) {
			log.error("Missing LDAP stores configuration trustbroker.config.ldap.stores");
			return templates;
		}

		for (Map.Entry<String, LdapServiceEndpointConfig> entry : ldap.getStores().entrySet()) {
			var ldapConfig = entry.getValue();
			var authentication = ldapConfig.getAuthentication();
			if (ldapConfig.getUrl() == null || authentication == null
					|| authentication.getPassword() == null || authentication.getUsername() == null) {
				log.error("Invalid configuration for store: {}", entry.getKey());
				continue;
			}
			templates.put(entry.getKey(),
					new LazyLdapTemplateSupplier(entry.getKey(), ldapConfig, metricsService, ldapContextSourceRegistry));
		}

		return templates;
	}

	private static @NonNull LdapContextSource getLdapContextSource(LdapServiceEndpointConfig ldapConfig) {
		LdapContextSource context = new LdapContextSource();
		context.setUrl(ldapConfig.getUrl());
		context.setUserDn(ldapConfig.getAuthentication().getUsername());
		context.setPassword(ldapConfig.getAuthentication().getPassword());

		// JNDI timeouts so a slow/unreachable directory does not block worker threads indefinitely
		Map<String, Object> baseEnvironment = getBaseEnvironment(ldapConfig);
		context.setBaseEnvironmentProperties(baseEnvironment);
		return context;
	}

	private static @NonNull Map<String, Object> getBaseEnvironment(LdapServiceEndpointConfig ldapConfig) {
		var network = ldapConfig.getNetwork();
		Map<String, Object> baseEnvironment = new HashMap<>();
		if (network == null) {
			log.warn("Missing network configuration for store endpoint: {}", ldapConfig.getUrl());
		}
		else {
			var connectTimeoutSec = network.getBackendConnectTimeoutSec();
			var responseTimeoutSec = network.getBackendResponseTimeoutSec();
			baseEnvironment.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(connectTimeoutSec * 1000L));
			baseEnvironment.put("com.sun.jndi.ldap.read.timeout", String.valueOf(responseTimeoutSec * 1000L));
		}
		// Binary AD attributes must be returned as byte[] (not decoded as String) so they can be converted properly
		baseEnvironment.put("java.naming.ldap.attributes.binary", LdapAttributeUtil.BINARY_ATTRIBUTES);
		return baseEnvironment;
	}

	/**
	 * Wraps the target {@link LdapContextSource} into a pooling {@link PooledContextSource} when pooling is enabled for the
	 * endpoint. Without pooling every LDAP operation opens a new connection (TCP + bind) to the directory server.
	 */
	private static @NonNull ContextSource addPoolingConfigIfEnabled(LdapContextSource context, LdapServiceEndpointConfig ldapConfig) {
		var pool = ldapConfig.getPool();
		if (pool == null || !pool.isEnabled()) {
			return context;
		}

		var poolConfig = new PoolConfig();
		poolConfig.setMaxTotalPerKey(pool.getMaxTotalPerKey());
		poolConfig.setMaxIdlePerKey(pool.getMaxIdlePerKey());
		poolConfig.setMinIdlePerKey(pool.getMinIdlePerKey());
		poolConfig.setMaxWaitMillis(pool.getMaxWaitSec() * 1000L);
		poolConfig.setTestWhileIdle(pool.isTestWhileIdle());
		poolConfig.setTimeBetweenEvictionRunsMillis(pool.getTimeBetweenEvictionRunsSec() * 1000L);
		poolConfig.setMinEvictableIdleTimeMillis(pool.getMinEvictableIdleTimeSec() * 1000L);

		var pooledContextSource = new PooledContextSource(context, poolConfig);

		// Validation is required for testWhileIdle to detect and drop broken pooled connections
		if (pool.isTestWhileIdle()) {
			pooledContextSource.setDirContextValidator(new DefaultDirContextValidator());
		}

		return pooledContextSource;
	}

	private static boolean hasSupportedScheme(String url) {
		return url != null && (url.regionMatches(true, 0, "ldap://", 0, 7)
				|| url.regionMatches(true, 0, "ldaps://", 0, 8));
	}

	private static class LazyLdapTemplateSupplier implements Supplier<LdapTemplate> {

		private final String storeName;

		private final LdapServiceEndpointConfig ldapConfig;

		private final MetricsService metricsService;

		private final LdapContextSourceRegistry ldapContextSourceRegistry;

		private final AtomicReference<LdapTemplate> delegate = new AtomicReference<>();

		private LazyLdapTemplateSupplier(String storeName, LdapServiceEndpointConfig ldapConfig, MetricsService metricsService,
				LdapContextSourceRegistry ldapContextSourceRegistry) {
			this.storeName = storeName;
			this.ldapConfig = ldapConfig;
			this.metricsService = metricsService;
			this.ldapContextSourceRegistry = ldapContextSourceRegistry;
		}

		@Override
		public LdapTemplate get() {
			var existing = delegate.get();
			if (existing != null) {
				return existing;
			}
			synchronized (delegate) {
				existing = delegate.get();
				if (existing != null) {
					return existing;
				}
				var start = System.currentTimeMillis();
				try {
					var created = getTemplate(ldapConfig, ldapContextSourceRegistry);
					delegate.set(created);
					var dTms = System.currentTimeMillis() - start;
					log.info("Initialized LDAP store '{}' in {} ms", storeName, dTms);
					if (metricsService != null) {
						metricsService.recordTimer("trustbroker.ldap.store.init", dTms, TimeUnit.MILLISECONDS, "store", storeName);
					}
					return created;
				}
				catch (RuntimeException e) {
					if (metricsService != null) {
						metricsService.incrementCounter("trustbroker.ldap.store.init.failures", "store", storeName);
					}
					log.error("Failed to initialize LDAP store '{}': {}", storeName, e.getMessage(), e);
					throw new TechnicalException("Failed to initialize LDAP store '" + storeName + "'", e);
				}
			}
		}
	}

	private static @NonNull LdapTemplate getTemplate(LdapServiceEndpointConfig ldapConfig,
			LdapContextSourceRegistry ldapContextSourceRegistry) {
		if (!hasSupportedScheme(ldapConfig.getUrl())) {
			throw new TechnicalException("Invalid LDAP URL scheme for store endpoint: " + ldapConfig.getUrl());
		}
		LdapContextSource context = getLdapContextSource(ldapConfig);

		// Must call afterPropertiesSet() to properly initialize the context source
		// This sets up the authenticationSource and other internal state required for LDAP operations
		try {
			context.afterPropertiesSet();
		}
		catch (Exception e) {
			throw new TechnicalException("Failed to initialize LDAP context source for endpoint: " + ldapConfig.getUrl(), e);
		}

		var contextSource = addPoolingConfigIfEnabled(context, ldapConfig);
		if (contextSource instanceof PooledContextSource pooledContextSource) {
			// the pooled source is not a managed bean, so the registry closes it on application context shutdown
			ldapContextSourceRegistry.register(pooledContextSource);
		}

		LdapTemplate template = new LdapTemplate(contextSource);

		// Optional: make LDAP failures non-fatal during queries
		template.setIgnorePartialResultException(true);
		return template;
	}
}
