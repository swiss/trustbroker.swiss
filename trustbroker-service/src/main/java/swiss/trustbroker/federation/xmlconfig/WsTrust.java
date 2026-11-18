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
import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * WS-Trust configuration for RP.
 * @since 1.14.0
 */
@XmlRootElement(name = "WsTrust")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WsTrust implements Serializable {

	/**
	 * WS-Trust protocol enabled.
	 * <br/>
	 * Default: true
	 */
	@Default("true")
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * For CPs use this <code>WsTrust</code> setting as default for all RPs used in combination with this CP.
	 * And vice versa for RPs.
	 * <br/>
	 * Default: false
	 */
	@Default("false")
	@XmlAttribute(name = "counterPartyDefault")
	private Boolean counterPartyDefault;

	/**
	 * List of supported inbound WS-Trust bindings.
	 * <br/>
	 * Default: Bindings enabled in global configuration (since 1.14.0, before all bindings were allowed)
	 *
	 * @see swiss.trustbroker.config.dto.WsTrustConfig#getBindings()
	 */
	@XmlElement(name = "SupportedBinding")
	private List<WsTrustBinding> supportedBindings;
}
