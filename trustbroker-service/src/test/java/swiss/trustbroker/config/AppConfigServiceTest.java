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

package swiss.trustbroker.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static swiss.trustbroker.config.TestConstants.LATEST_INVALID_DEFINITION_PATH;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opensaml.security.credential.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.federation.xmlconfig.SignerTruststore;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.ClientConfigInMemoryRepository;
import swiss.trustbroker.oidc.OidcEncryptionKeystoreService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.DefaultHandler;

@SpringBootTest
@ContextConfiguration(classes = { AppConfigService.class })
class AppConfigServiceTest {

	@MockitoBean
	private ApplicationEventPublisher eventPublisher;

	@MockitoBean
	private TrustBrokerProperties properties;

	@MockitoBean
	private GitService gitService;

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private ClientConfigInMemoryRepository clientConfigInMemoryRepository;

	@MockitoBean
	private MetricsService metricsService;

	@MockitoBean
	private XmlConfigStatusService xmlConfigStatusService;

	@MockitoBean
	private OidcMetadataCacheService oidcMetadataCacheService;

	@MockitoBean
	private WebResourceProvider resourceProvider;

	@MockitoBean
	private CredentialService credentialService;

	@MockitoBean
	private OidcEncryptionKeystoreService oidcEncryptionKeystoreService;

	@MockitoBean
	private DefaultHandler defaultHandler;

	@Autowired
	private AppConfigService appConfigService;

	@ParameterizedTest
	@CsvSource({
			// Linux: strip the last path segment and append the cache path
			"/home/user/trustbroker-inventories/profile,     /home/user/trustbroker-inventories/configCache/trustbroker-inventories/",
			// Linux: deeper nesting — still strips only one trailing segment
			"/opt/app/config/current,                        /opt/app/config/configCache/trustbroker-inventories/",
			// Windows C:\ prefix: backslashes are converted and "C:" becomes "/c"
			"C:\\config\\trustbroker-inventories\\profile,   /c/config/trustbroker-inventories/configCache/trustbroker-inventories/"
	})
	void getConfigCachePathTest(String configurationPath, String expectedCachePath) {
		assertEquals(expectedCachePath.strip(), AppConfigService.getConfigCachePath(configurationPath.strip()));
	}

	@Test
	void checkAndLoadCpCertificatesTest() {
		// cp1: no certificates → skipped early, stays valid, no credentials loaded
		var cp1 = ClaimsParty.builder().id("cp1").build();

		// cp2: signer truststore only → stays valid, cpTrustCredential is populated
		var signerTruststore = SignerTruststore.builder().build();
		var certificates = Certificates.builder().signerTruststore(signerTruststore).build();
		var cp2 = ClaimsParty.builder().id("cp2").certificates(certificates).build();
		List<Credential> mockCredentials = List.of();
		doReturn(mockCredentials).when(credentialService).checkAndLoadTrustCredential(any(), eq("cp2"), any());

		// cp3: credential service throws TechnicalException → CP is invalidated, no exception propagated
		var cp3 = ClaimsParty.builder().id("cp3").certificates(certificates).build();
		doThrow(new TechnicalException("cert load failure")).when(credentialService).checkAndLoadTrustCredential(any(), eq("cp3"), any());

		var setup = ClaimsProviderSetup.builder().claimsParties(List.of(cp1, cp2, cp3)).build();

		assertDoesNotThrow(() -> appConfigService.checkAndLoadCpCertificates(setup));

		// cp1: no certs → valid, nothing was set
		assertThat(cp1.isValid(), is(true));
		assertThat(cp1.getCpTrustCredential(), nullValue());

		// cp2: valid, credentials populated
		assertThat(cp2.isValid(), is(true));
		assertThat(cp2.getCpTrustCredential(), is(mockCredentials));

		// cp3: invalidated because TechnicalException was caught
		assertThat(cp3.isValid(), is(false));
	}

	@Test
	void checkAndLoadRelyingPartyCertificatesTest() {
		// rp1: no certificates → early return, stays valid, no signer set
		var rp1 = RelyingParty.builder().id("rp1").build();

		// rp2: with signer keystore + truststore, OIDC/SAML disabled → valid, credentials loaded
		var certificates = Certificates.builder()
				.signerKeystore(SignerKeystore.builder().build())
				.signerTruststore(SignerTruststore.builder().build())
				.build();
		var rp2 = RelyingParty.builder().id("rp2").certificates(certificates).build();
		var mockSignerCredential = mock(Credential.class);
		doReturn(mockSignerCredential).when(credentialService).checkAndLoadCert(any(), eq("rp2"), any());
		doReturn(List.of()).when(credentialService).checkAndLoadTrustCredential(any(), eq("rp2"), any());
		// prevent NPE: isOidcEnabled/isSamlEnabled call properties.getOidc()/getSaml()
		doReturn(mock(OidcProperties.class)).when(properties).getOidc();
		doReturn(mock(SamlProperties.class)).when(properties).getSaml();

		// rp3: TechnicalException from credentialService → first catch block, RP invalidated
		var rp3 = RelyingParty.builder().id("rp3").certificates(certificates).build();
		doThrow(new TechnicalException("cert error")).when(credentialService).checkAndLoadCert(any(), eq("rp3"), any());

		// rp4: generic Exception from credentialService → second catch block, RP also invalidated
		var rp4 = RelyingParty.builder().id("rp4").certificates(certificates).build();
		doThrow(new RuntimeException("unexpected error")).when(credentialService).checkAndLoadCert(any(), eq("rp4"), any());

		var setup = RelyingPartySetup.builder().relyingParties(List.of(rp1, rp2, rp3, rp4)).build();

		assertDoesNotThrow(() -> appConfigService.checkAndLoadRelyingPartyCertificates(setup));

		// rp1: no certs → valid, nothing loaded
		assertThat(rp1.isValid(), is(true));
		assertThat(rp1.getRpSigner(), nullValue());

		// rp2: valid, signer credential and trust credentials populated
		assertThat(rp2.isValid(), is(true));
		assertThat(rp2.getRpSigner(), is(mockSignerCredential));
		assertThat(rp2.getRpTrustCredentials(), is(List.of()));

		// rp3: TechnicalException → invalidated
		assertThat(rp3.isValid(), is(false));

		// rp4: generic Exception → also invalidated
		assertThat(rp4.isValid(), is(false));
	}

	@Test
	void TestCheckRpSsoIntegrity() {
		var ssoGroup = SsoGroup.builder().name("sso1").build();
		var rpOk = RelyingParty.builder()
							   .id("rp3")
							   .sso(Sso.builder().enabled(true).groupName(ssoGroup.getName()).build())
							   .build();
		var rpUnknownSsoGroup = RelyingParty.builder()
											.id("rp1")
											.sso(Sso.builder().enabled(true).groupName("unknown").build())
											.build();
		var rpMissingSsoGroup = RelyingParty.builder()
											.id("rp2")
											.sso(Sso.builder().enabled(true).build())
											.build();
		var rpSetup = RelyingPartySetup.builder().relyingParties(List.of(rpOk, rpMissingSsoGroup, rpUnknownSsoGroup)).build();
		var ssoSetup = SsoGroupSetup.builder().ssoGroups(List.of(ssoGroup)).build();

		AppConfigService.checkRpSsoIntegrity(rpSetup, ssoSetup);

		assertThat(rpOk.isValid(), is(true));
		assertThat(rpOk.getValidationStatus().getErrors(), hasSize(0));
		assertThat(rpUnknownSsoGroup.isValid(), is(true));
		assertThat(rpUnknownSsoGroup.getValidationStatus().getErrors(), hasSize(1));
		assertThat(rpMissingSsoGroup.isValid(), is(true));
		assertThat(rpMissingSsoGroup.getValidationStatus().getErrors(), hasSize(1));
	}

	@Test
	void testInvalidBase() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidBase.xml");
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList(), scriptService, claimsProviderSetup, null, null));
		var rp = relyingPartySetup.getRelyingParties().getFirst();
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	@Test
	void loadConfigFromFileInvalidFile() {
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidCert.xml");
		doThrow(TechnicalException.class).when(credentialService).checkAndLoadCert(any(), any(), any());
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList(), scriptService, claimsProviderSetup, null, null));
		var rp = relyingPartySetup.getRelyingParties().getFirst();

		appConfigService.checkAndLoadRelyingPartyCertificates(relyingPartySetup);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	private RelyingPartySetup loadRelyingParty(String fileName) {
		var file = SamlTestBase.fileFromClassPath(LATEST_INVALID_DEFINITION_PATH + fileName);
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(file, null);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(1));
		var rp = relyingPartySetup.getRelyingParties().getFirst();
		// after loading, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		return relyingPartySetup;
	}
}
