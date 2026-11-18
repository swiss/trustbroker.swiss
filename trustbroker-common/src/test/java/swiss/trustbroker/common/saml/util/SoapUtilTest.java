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

package swiss.trustbroker.common.saml.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang3.tuple.Pair;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.soap.util.SOAPConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class SoapUtilTest {

	private static final String SOAP_REQUEST = """
			<?xml version="1.0" encoding="UTF-8"?>
			<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"
							 xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_envelope1">
			  <soap11:Header ID="_body1">
				<saml2p:Assertion ID="Assertion1">
				</saml2p:Assertion>
			  </soap11:Header>
			  <soap11:Body ID="_body1">
				<saml2p:ArtifactResolve
					Destination="http://localhost:7070/authn/arp" ID="_3f033b15974261f5f5a3f634daaf0b1a"
					IssueInstant="2023-05-10T13:56:39.660Z" Version="2.0">
				  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:MOCK</saml2:Issuer>
				  <saml2p:Artifact>AAQAAJc1A9VaukDonUq0wWeDvJoVnFEuzbT/fK/T9M3bxQyDBNKHlujCoeE=</saml2p:Artifact>
				</saml2p:ArtifactResolve>
			  </soap11:Body>
			</soap11:Envelope>
			""";

	private static final String EXPECTED_ID = "_3f033b15974261f5f5a3f634daaf0b1a";

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void extractSamlObjectFromEnvelope() {
		var envelope = givenEnvelope();
		var result = SoapUtil.extractSamlObjectFromEnvelope(envelope, ArtifactResolve.class);

		assertThat(result.getID(), is(EXPECTED_ID));
	}

	@Test
	void sendSoap11ResponseAndExtractSamlObject() {
		var issuerId = "issuer1Id";
		var samlResponse = SamlFactory.createResponse(Response.class, issuerId);
		var response = new MockHttpServletResponse();
		SoapUtil.sendSoap11Response(response, samlResponse);
		var envelope = SoapUtil.readEnvelope(new ByteArrayInputStream(response.getContentAsByteArray()));
		var result = SoapUtil.extractSamlObjectFromEnvelope(envelope, Response.class);
		assertThat(result.getIssuer().getValue(), is(issuerId));
	}

	@Test
	void isSignatureValid() throws Exception {
		var keyStore = SamlTestBase.dummyCredential();
		var trustStore = SamlTestBase.dummyCredentials();
		var wrongTrustStore = SamlTestBase.dummyInvalidCredential();
		var envelope = givenEnvelope();
		List<Pair<String, String>> idAttributes = givenIdAttributes();
		List<Pair<String, String>> acceptedSignedElements = givenAcceptedSignedElements();
		var acceptedSignedArtifactResolve = List.of(Pair.of(SAMLConstants.SAML20P_NS, "ArtifactResolve"));
		var acceptedSignedEnvelope = List.of(Pair.of(SOAPConstants.SOAP11_NS, "Envelope"));
		var params = givenSignatureParameters();
		var signature = SoapUtil.signElement(envelope.ensureDOM(), EXPECTED_ID, params, keyStore);

		// Signature is valid if matching second entry in truststore:
		var combinedTruststore = Stream.of(wrongTrustStore, trustStore).flatMap(List::stream).toList();
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes,
				acceptedSignedArtifactResolve, combinedTruststore), is(true));

		// Signature is valid for the signed ArtifactResolve element:
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes,
						acceptedSignedArtifactResolve, trustStore), is(true));
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes, acceptedSignedElements, trustStore),
				is(true));
		// Checking just the ArtifactResolve element also works (optional):
		var artifactResolve = envelope.getBody().getOrderedChildren().getFirst();
		assertThat(SoapUtil.isSignatureValid(artifactResolve.ensureDOM(), signature, idAttributes,
				acceptedSignedArtifactResolve, trustStore), is(true));

		// Signature validation with wrong trust store fails:
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes,
				acceptedSignedArtifactResolve, wrongTrustStore), is(false));

		// ArtifactResolve is signed, but rejected if not in accepted list of signed elements:
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes, acceptedSignedEnvelope, trustStore),
				is(false));

		// Envelope is not signed, so signature is invalid:
		assertThat(SoapUtil.isSignatureValid(envelope.ensureDOM(), signature, idAttributes, acceptedSignedEnvelope, trustStore),
				is(false));

		// Unrelated Assertion element in header is not signed, so signature is invalid:
		var assertion = envelope.getHeader().getOrderedChildren().getFirst();
		assertThat(SoapUtil.isSignatureValid(assertion.ensureDOM(), signature, idAttributes, acceptedSignedEnvelope, trustStore),
				is(false));

		// Element with same ID and type but not in the envelope is not considered signed:
		var unrelatedElement = givenDocumentWithElement(SAMLConstants.SAML20P_NS, "ArtifactResolve", EXPECTED_ID);
		assertThat(SoapUtil.isSignatureValid(unrelatedElement, signature, idAttributes, acceptedSignedElements, trustStore),
				is(false));
		assertThat(SoapUtil.isSignatureValid(unrelatedElement.getOwnerDocument().getDocumentElement(), signature, idAttributes,
						acceptedSignedElements, trustStore),
				is(false));
	}

	private static @NonNull List<Pair<String, String>> givenIdAttributes() {
		return List.of(Pair.of(null, "Id"), Pair.of(null, "ID"));
	}

	private static SignatureParameters givenSignatureParameters() {
		return SignatureParameters.builder()
		                          .credential(SamlTestBase.dummyCredential())
		                          .signatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256)
		                          .canonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N11_OMIT_COMMENTS)
		                          .digestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256)
		                          .build();
	}

	private static Element givenDocumentWithElement(String elementNs, String elementName, String elementId) throws Exception {
		var factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		var document = factory.newDocumentBuilder().newDocument();
		var element = document.createElementNS(elementNs, elementName);
		if (elementId != null) {
			element.setAttribute("ID", elementId);
		}
		document.appendChild(element);
		return element;
	}

	private static List<Pair<String, String>> givenAcceptedSignedElements() {
		return List.of(
				Pair.of(SOAPConstants.SOAP11_NS, "Envelope"),
				Pair.of(SOAPConstants.SOAP11_NS, "Body"),
				Pair.of(SAMLConstants.SAML20P_NS, "Assertion"),
				Pair.of(SAMLConstants.SAML20P_NS, "ArtifactResolve"));
	}

	private static Envelope givenEnvelope() {
		var in = new ByteArrayInputStream(SOAP_REQUEST.getBytes(StandardCharsets.UTF_8));
		return SoapUtil.readEnvelope(in);
	}
}
