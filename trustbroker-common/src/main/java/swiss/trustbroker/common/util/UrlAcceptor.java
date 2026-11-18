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

package swiss.trustbroker.common.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;

@Slf4j
public class UrlAcceptor {

	@SuppressWarnings("java:S1075")
	private static final String SUBPATH_MATCH = "/.*";

	private UrlAcceptor() {
	}

	// Check HTTP Origin header against configured ACLs
	public static boolean isTrustedOrigin(String origin, Collection<? extends AcceptedUrl> acUrls) {
		return isUrlOkForAccess(origin, acUrls, true);
	}

	public static boolean isRedirectUrlOkForAccess(String requestedRedirectUri, Collection<? extends AcceptedUrl> acUrls) {
		return isUrlOkForAccess(requestedRedirectUri, acUrls, false);
	}

	private static boolean isUrlOkForAccess(String check, Collection<? extends AcceptedUrl> acUrls, boolean ignorePath) {
		if (check == null || acUrls == null) {
			return false;
		}
		try {
			var uri = new URI(check);
			if (uri.getUserInfo() != null) {
				log.error("userinfo@ not allowed in url=\"{}\"", check);
				return false;
			}
			if (isLocalhostAccess(uri.getHost())) {
				return localhostUrlOkForAccess(check, acUrls, ignorePath);
			}
		}
		catch (URISyntaxException | NullPointerException ex) {
			log.error("Invalid url=\"{}\" : {}", check, ex.toString());
		}
		return acUrls.stream().anyMatch(acUri -> isUrlOkForAccess(check, acUri, ignorePath));
	}

	// Check URLs including localhost special semantics but accept regexp on path and /.* as not having a sub-path,
	// so we do not have to configure https:/host/.* and https://host twice.
	// (variant with URI, URI not used at the moment)
	public static boolean isUrlOkForAccess(URI check, AcceptedUrl accept) {
		return isUrlOkForAccess(check, accept, false);
	}

	// same ignoring the path
	// (variant with URI, AcceptedUrl not used at the moment)
	public static boolean isUrlOkForAccessIgnoringPath(URI check, URI accept) {
		return isUrlOkForAccess(check, accept, null, AcceptedUrlFormat.FULL, true);
	}

	private static boolean isUrlOkForAccess(URI check, AcceptedUrl accept, boolean ignorePath) {
		if (accept == null || accept.getFormat() == AcceptedUrlFormat.IGNORED) {
			return false;
		}
		// regex can be an invalid URL or URL parts are not properly assigned - ignorePath ignored as we cannot split the regex
		if (accept.getFormat() == AcceptedUrlFormat.REGEX) {
			return check.toString().matches(accept.getUrl());
		}
		if (accept.getUri() == null) {
			log.warn("Missing URI for format={} AcUrl=\"{}\"", accept.getFormat(), accept.getUrl());
		}
		return isUrlOkForAccess(check, accept.getUri(), accept.getPattern(), accept.getFormat(), ignorePath);
	}

	private static boolean isUrlOkForAccess(URI check, URI accept, Pattern pattern, AcceptedUrlFormat format,
			boolean ignorePath) {
		if (check == null || accept == null) {
			return false;
		}
		var isLocalHost = isLocalhostAccess(check.getHost());
		return // no relative URLs allowed
				check.isAbsolute() && accept.isAbsolute() &&
						isSchemeMatching(check, accept) &&
						isHostMatching(check, accept, isLocalHost) &&
						isPortMatching(check, accept, isLocalHost) &&
						(ignorePath || isPathMatching(check, accept, pattern, format));
	}

	// protocol must match exactly
	private static boolean isSchemeMatching(URI check, URI accept) {
		return check.getScheme().equals(accept.getScheme());
	}

	// host must match exactly or both must be localhost addresses
	private static boolean isHostMatching(URI check, URI accept, boolean isLocalHost) {
		return check.getHost().equals(accept.getHost())
				|| (isLocalHost && isLocalhostAccess(accept.getHost()));
	}

	// port must match if not default or not 0 signaling any port on localhost
	private static boolean isPortMatching(URI check, URI accept, boolean isLocalHost) {
		return check.getPort() == accept.getPort()
				|| (accept.getPort() == -1 && check.getPort() == HttpUtil.getDefaultPort(accept))
				|| (check.getPort() == -1 && accept.getPort() == HttpUtil.getDefaultPort(check))
				|| (isLocalHost && accept.getPort() == 0);
	}

	// path must match by regexp including /.* or without it (top-level resource access allowed)
	private static boolean isPathMatching(URI check, URI accept, Pattern pattern, AcceptedUrlFormat format) {
		return switch (format) {
			case FULL -> fullMatch(check.getPath(), accept.getPath());
			case PREFIX -> prefixMatch(check.getPath(), accept.getPath());
			case REGEX, IGNORED -> false; // handled before
			case PATH_REGEX -> regexMatch(check.getPath(), accept.getPath(), pattern);
			// legacy matching:
			case ANY -> check.getPath().equals(accept.getPath())
					|| (check.getPath() + SUBPATH_MATCH).equals(accept.getPath()) // handle exact match without a trailing /
					|| check.getPath().matches(accept.getPath());
		};
	}

	private static boolean fullMatch(String check, String accept) {
		return check.equals(accept);
	}

	private static boolean prefixMatch(String check, String accept) {
		if (fullMatch(check, accept)) {
			return true;
		}
		if (accept.endsWith("/")) {
			return check.startsWith(accept) || (check + '/').startsWith(accept);
		}
		return check.startsWith(accept + '/');
	}

	private static boolean regexMatch(String check, String accept, Pattern pattern) {
		if (pattern == null) {
			if (accept == null) {
				log.warn("Missing pattern and accept URL - cannot match url='{}'", check);
				return false;
			}
			pattern = Pattern.compile(accept);
		}
		return pattern.matcher(check).matches();
	}

	static boolean isUrlOkForAccess(String check, AcceptedUrl accept, boolean ignorePath) {
		try {
			return isUrlOkForAccess(new URI(check), accept, ignorePath);
		}
		catch (URISyntaxException | NullPointerException e) {
			log.error("Deny invalid url={} checked against acUrl={} ({})", check, accept, e.getMessage());
			return false;
		}
	}

	// Inspired by OAuth2AuthorizationCodeRequestAuthenticationValidator.isLoopbackAddress
	private static boolean isLocalhostAccess(String host) {
		if (!StringUtils.hasText(host)) {
			return false;
		}
		if (host.equals("localhost") || host.equals("localhost.localdomain")) {
			return true; // speed up as DNS lookups are expensive
		}
		if ("[0:0:0:0:0:0:0:1]".equals(host) || "[::1]".equals(host)) {
			return true;
		}
		// handle IP addresses too even though we cannot see if the client was manipulated to forward localhost to bad server
		try {
			// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
			var ipv4Octets = host.split("\\.");
			if (ipv4Octets.length != 4) {
				return false;
			}
			var address = new int[ipv4Octets.length];
			for (int i = 0; i < ipv4Octets.length; i++) {
				address[i] = Integer.parseInt(ipv4Octets[i]);
			}
			return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 &&
					address[2] <= 255 && address[3] >= 1 && address[3] <= 255;
		}
		catch (Exception ex) {
			// info would be interesting, but we cannot assume that service has the clients DNS resolv.conf
			log.debug("Handling host={} for localhost check failed with exception: {}", host, ex.getMessage());
			return false;
		}
	}

	// format ANY accept http://localhost/.* as http://localhost too and also handle default ports
	private static boolean localhostUrlOkForAccess(String check, AcceptedUrl aclUri, boolean ignorePath) {
		if (aclUri.getFormat() == AcceptedUrlFormat.IGNORED) {
			return false;
		}
		var match = switch (aclUri.getFormat()) {
			case FULL, IGNORED -> false;
			case REGEX, PATH_REGEX -> regexMatch(check, aclUri.getUrl(), aclUri.getPattern());
			case PREFIX -> prefixMatch(check, aclUri.getUrl());
			// legacy matching:
			case ANY -> check.matches(aclUri.getUrl()) // regexp match only
					|| check.matches(aclUri.getUrl().replace(SUBPATH_MATCH, "")); // regexp match but skip sub-path
		};
		return match || isUrlOkForAccess(check, aclUri, ignorePath); // OIDC check aligned with SAML check
	}

	// Use regex validation for localhost URLs of format https?://localhost:?(.*?)/?
	private static boolean localhostUrlOkForAccess(String check, Collection<? extends AcceptedUrl> aclUris, boolean ignorePath) {
		return check != null && aclUris != null &&
				aclUris.stream().anyMatch(configUri -> localhostUrlOkForAccess(check, configUri, ignorePath));
	}

}
