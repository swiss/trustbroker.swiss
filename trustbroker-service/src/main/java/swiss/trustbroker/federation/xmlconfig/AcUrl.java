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
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import jakarta.xml.bind.annotation.XmlValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import swiss.trustbroker.common.dto.AcceptedUrl;
import swiss.trustbroker.common.dto.AcceptedUrlFormat;
import swiss.trustbroker.common.util.WebUtil;

/**
 * AC URL
 * @since 1.16.0
 */
@XmlRootElement(name = "ACUrl")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class AcUrl implements AcceptedUrl, Serializable {

	// This is the default for elements created in the code. The global default from TrustBrokerProperties is applied to XML only.
	private static final AcceptedUrlFormat DEFAULT_FORMAT = AcceptedUrlFormat.FULL;

	/**
	 * Convenience converter.
	 * @return instance with format set to FULL, or REGEX if not a valid URI
	 */
	public static AcUrl of(String url) {
		return ofFormat(url, null, true);
	}

	/**
	 * Convenience converter.
	 * @return instance with given format set (null: if not valid URI REGEX is set, else null is set)
	 */
	public static AcUrl ofFormat(String url, AcceptedUrlFormat format) {
		return ofFormat(url, format, false);
	}

	private static AcUrl ofFormat(String url, AcceptedUrlFormat format, boolean setDefaultFormat) {
		var uri = WebUtil.getValidatedUri(url);
		if (uri == null) {
			if (format == null) {
				format = AcceptedUrlFormat.REGEX;
				log.debug("Derived format={} from invalid  URI url=\"{}\"", format, url);
			}
			log.atLevel(format == AcceptedUrlFormat.REGEX ? Level.DEBUG : Level.WARN)
			   .log("ACUrl of format={} is not a valid URI url=\"{}\"", format, url);
		}
		else if (format == null && setDefaultFormat) {
			format = DEFAULT_FORMAT;
			log.debug("Derived format={} from valid URI url=\"{}\"", format, url);
		}
		var acUrl = builder()
				.url(url)
				.format(format)
				.uri(uri)
				.build();
		acUrl.derivePattern(Optional.empty());
		return acUrl;
	}

	/**
	 * Convenience converter.
	 * @return instances of format FULL
	 */
	@SuppressWarnings("java:S1168") // converter may return null
	public static List<AcUrl> asAcUrlList(Collection<String> urls) {
		if (urls == null) {
			return null;
		}
		return urls.stream().map(AcUrl::of).toList();
	}

	/**
	 * Convenience converter.
	 * @return instances of format FULL
	 */
	@SuppressWarnings("java:S1168") // converter may return null
	public static Set<AcceptedUrl> asAcceptedUrlSet(Collection<String> urls) {
		if (urls == null) {
			return null;
		}
		return urls.stream().map(AcUrl::of).collect(Collectors.toSet());
	}

	/**
	 * AC URL format.
	 * <br/>
	 * Default: Global config <code>trustbroker.config.defaultAcUrlFormat} or FULL if not set</code>.
	 */
	@Default(value = "trustbroker.config.defaultAcUrlFormat", format = DefaultFormat.PROPERTY, fallback = "FULL")
	@XmlAttribute(name = "format")
	private AcceptedUrlFormat format;

	/**
	 * AC URL value (URL or regex).
	 */
	@XmlValue
	private String url;

	@XmlTransient
	private URI uri;

	@XmlTransient
	private String patternString;

	@XmlTransient
	@EqualsAndHashCode.Exclude // equals not based on pattern String, ignore
	private Pattern pattern;

	/**
	 * Derive transitive pattern values. May throw an exception if pattern compilation fails
	 */
	void derivePattern(Optional<Consumer<String>> errorCallback) {
		var checkFormat = format != null ? format : DEFAULT_FORMAT;
		patternString = null;
		pattern = null;
		if (checkFormat == AcceptedUrlFormat.REGEX) {
			patternString = url;
		}
		else if (checkFormat == AcceptedUrlFormat.PATH_REGEX && uri != null) {
			patternString = uri.getPath();
		}
		if (patternString != null) {
			try {
				pattern = Pattern.compile(patternString);
			}
			catch (PatternSyntaxException ex) {
				var msg = String.format("Ignoring AcUrl with invalid pattern=\"%s\" for format=%s url=\"%s\"",
						patternString, checkFormat, url);
				log.error(msg, ex);
				format = AcceptedUrlFormat.IGNORED;
				errorCallback.ifPresent(consumer -> consumer.accept(msg));
			}
		}
	}
}
