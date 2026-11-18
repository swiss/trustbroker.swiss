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

import java.util.ArrayList;
import java.util.List;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ldap.pool2.factory.PooledContextSource;

/**
 * Tracks the {@link PooledContextSource} instances created lazily per LDAP store.
 * <br/>
 * The pooled sources are built inside a lazy supplier and are therefore not managed beans, so the container would never
 * invoke their destroy callback. Without that callback the commons-pool evictor thread and the pooled LDAP contexts stay
 * alive across application context shutdown or reload. This registry is a managed bean and closes them on shutdown.
 *
 * @since 1.16.0
 */
@Slf4j
public class LdapContextSourceRegistry {

	private final List<PooledContextSource> pools = new ArrayList<>();

	private boolean destroyed;

	/**
	 * Registers a lazily created pooled context source for shutdown.
	 * <br/>
	 * If the registry was already destroyed the source is closed immediately, so a store initialized during or after
	 * shutdown cannot leak its evictor thread.
	 */
	public synchronized void register(PooledContextSource pool) {
		if (destroyed) {
			log.info("Closing pooled LDAP context source created after shutdown");
			close(pool);
			return;
		}
		pools.add(pool);
	}

	@PreDestroy
	public synchronized void destroy() {
		destroyed = true;
		if (!pools.isEmpty()) {
			log.info("Closing {} pooled LDAP context source(s)", pools.size());
		}
		pools.forEach(LdapContextSourceRegistry::close);
		pools.clear();
	}

	// PooledContextSource has no close(), it implements DisposableBean.destroy() which declares a checked exception
	private static void close(PooledContextSource pool) {
		try {
			pool.destroy();
		}
		catch (Exception e) {
			log.error("Failed to close pooled LDAP context source: {}", e.getMessage(), e);
		}
	}

}

