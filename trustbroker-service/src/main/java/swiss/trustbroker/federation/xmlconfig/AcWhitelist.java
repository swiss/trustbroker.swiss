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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Consumer;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.WebUtil;

/**
 * Whitelist of Assertion consumer service URLs / OIDC redirect URLs.
 */
@XmlRootElement(name = "ACWhitelist")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@Slf4j
public class AcWhitelist implements Serializable {

	/**
	 * Use the first entry as default if the RP does not send an ACS URL.
	 * <br/>
	 * So far only supported for SAML.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.11.0
	 */
	@XmlAttribute(name = "useDefault")
	@Builder.Default
	private Boolean useDefault = false;

	/**
	 * List of allowed URLs.
	 */
	@XmlElement(name = "ACUrl")
	private List<AcUrl> acUrls;

	@XmlTransient
	private List<AcceptedUrl> redirectUrls;

	@XmlTransient
	private List<String> origins;

	@XmlTransient
	private Set<AcceptedUrl> originSet;

	/**
	 * Allowed frame ancestors for iframes.
	 * <br/>
	 * Overrides origins derived from ACUrl if set (even if configured as an empty list).
	 *
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors">CSP frame-ancestors</a>
 	 */
	@XmlElement(name = "FrameAncestor")
	private List<String> frameAncestors;

	public AcWhitelist() {
		this(null, null, null, null, null, null);
	}

	public AcWhitelist(List<AcUrl> acUrls) {
		this(null, acUrls, null, null, null, null);
	}

	public AcWhitelist(Boolean useDefault, List<AcUrl> acUrls, List<AcceptedUrl> redirectUrls,
			List<String> origins, Set<AcceptedUrl> originSet,
			List<String> frameAncestors) {
		this.useDefault = useDefault;
		this.origins = origins;
		this.originSet = originSet;
		this.redirectUrls = redirectUrls;
		setAcUrls(acUrls);
		this.frameAncestors = frameAncestors;
	}

	public void setAcUrls(List<AcUrl> acUrls) {
		this.acUrls = acUrls;
		calculateDerivedUrls(Optional.empty());
	}

	// default format is null, the caller must apply the @Default of AcUrl later
	public void calculateDerivedUrls(Optional<Consumer<String>> errorCallback) {
		calculateDerivedUrls(null, errorCallback);
	}

	public void calculateDerivedUrls(AcceptedUrlFormat defaultFormat, Optional<Consumer<String>> errorCallback) {
		if (acUrls == null) {
			acUrls = new ArrayList<>();
		}
		redirectUrls = new ArrayList<>();
		origins = new ArrayList<>();
		originSet = new HashSet<>();
		for (var acUrl : acUrls) {
			calculateDerivedUrl(acUrl, defaultFormat, errorCallback);
		}
	}

	private void calculateDerivedUrl(AcUrl acUrl, AcceptedUrlFormat defaultFormat, Optional<Consumer<String>> errorCallback) {
		var url = WebUtil.getValidatedUri(acUrl.getUrl());
		acUrl.setUri(url); // URI needed in case acUrl is used for validation
		if (url == null || !url.isAbsolute()) {
			if (acUrl.getFormat() == AcceptedUrlFormat.REGEX) {
				log.info("ACUrl={} - is invalid or relative URL - accepted for REGEX", acUrl);
			}
			else {
				var msg = String.format("Ignoring ACUrl=%s - it is invalid, relative or a regex without regex format", acUrl);
				log.info(msg);
				acUrl.setFormat(AcceptedUrlFormat.IGNORED);
				errorCallback.ifPresent(consumer -> consumer.accept(msg));
			}
		}
		else {
			var validOrigin = WebUtil.getValidOrigin(url);
			if (validOrigin == null) {
				// happens e.g. with wildcards in domain names
				log.info("Ignoring url={} having scheme='{}' host='{}' authority='{}' (HINT: No regexp on these fields)",
						url, url.getScheme(), url.getHost(), url.getAuthority());
			}
			else {
				this.origins.add(validOrigin);
				this.originSet.add(AcUrl.of(validOrigin));
			}
			if (url.getRawFragment() == null) {
				this.redirectUrls.add(acUrl);
			}
			else {
				log.info("ACUrl={} contains a fragment - not a valid redirect URL", acUrl);
			}
		}
		if (acUrl.getFormat() == null) {
			acUrl.setFormat(defaultFormat);
			log.trace("ACUrl={} without format, set default format", acUrl);
		}
		acUrl.derivePattern(errorCallback);
	}

	public List<String> getFrameAncestorsWithFallback() {
		if (frameAncestors != null) {
			return frameAncestors;
		}
		return origins;
	}

	public Optional<String> getDefault() {
		if (!Boolean.TRUE.equals(useDefault) || CollectionUtils.isEmpty(acUrls)) {
			return Optional.empty();
		}
		return Optional.of(acUrls.getFirst().getUrl());
	}

	public Optional<String> findFirst(BiPredicate<String, String> matcher, String checkUrl) {
		return CollectionUtil.findSingleValueByPredicate(acUrls, acUrl -> matcher.test(acUrl.getUrl(), checkUrl))
							 .map(AcUrl::getUrl);
	}

	public Optional<String> findEqualWithDefault(String checkUrl) {
		Optional<String> consumer;
		if (checkUrl == null) {
			consumer = getDefault();
			log.debug("Missing ACUrl - using default='{}'", consumer.orElse(null));
		}
		else {
			consumer = findFirst(String::equals, checkUrl);
			log.debug("url='{}' matched whitelist entry ACUrl='{}'", checkUrl, consumer.orElse(null));
		}
		return consumer;
	}
}
