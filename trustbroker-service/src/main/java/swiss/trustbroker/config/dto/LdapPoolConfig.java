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

package swiss.trustbroker.config.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Connection pooling configuration for a named LDAP endpoint.
 * <br/>
 * Without pooling every LDAP operation opens a new connection (TCP + bind) to the directory server, which adds latency
 * and load. When pooling is enabled the underlying JNDI contexts are pooled and reused (backed by Spring LDAP
 * {@code PooledContextSource} / commons-pool2).
 *
 * @since 1.16.0
 */
@Data
@NoArgsConstructor
public class LdapPoolConfig {

	/**
	 * Enable connection pooling for the endpoint.
	 * <br/>
	 * Default: true
	 */
	private boolean enabled = true;

	/**
	 * Maximum number of active contexts per context type (read/write).
	 * <br/>
	 * Default: 5
	 */
	private int maxTotalPerKey = 5;

	/**
	 * Maximum number of idle contexts per context type (read/write) kept in the pool.
	 * <br/>
	 * Default: 2
	 */
	private int maxIdlePerKey = 2;

	/**
	 * Minimum number of idle contexts per context type (read/write) kept in the pool.
	 * <br/>
	 * Default: 0
	 */
	private int minIdlePerKey = 0;

	/**
	 * Maximum time in seconds to wait for a context to become available when the pool is exhausted.
	 * A negative value blocks indefinitely.
	 * <br/>
	 * Default: 5
	 */
	private long maxWaitSec = 5L;

	/**
	 * Validate idle contexts during eviction runs and drop invalid ones.
	 * <br/>
	 * Default: true
	 */
	private boolean testWhileIdle = true;

	/**
	 * Time in seconds between idle context eviction runs. A non-positive value disables the evictor.
	 * <br/>
	 * Default: 300 (5 minutes)
	 */
	private long timeBetweenEvictionRunsSec = 300L;

	/**
	 * Minimum time in seconds a context may sit idle before it is eligible for eviction.
	 * <br/>
	 * Default: 600 (10 minutes)
	 */
	private long minEvictableIdleTimeSec = 600L;

}

