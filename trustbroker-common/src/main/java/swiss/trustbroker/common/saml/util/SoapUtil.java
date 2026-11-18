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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.core.xml.ElementExtensibleXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import swiss.trustbroker.common.exception.ExceptionUtil;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SignatureParameters;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SoapUtil {

	private static final String MECHANISM_TYPE_DOM = "DOM";

	// https://docs.oracle.com/javase/8/docs/technotes/guides/security/xmldsig/XMLDigitalSignature.html#xmlsig-secure-validation-mode
	private static final String SECURE_VALIDATION = "org.jcp.xml.dsig.secureValidation";

	private static final String SIGNATURE_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

	private static final String SIGNATURE_NAME = "Signature";

	// standard usage: masked oneliners for errors
	public static String nodeObjectToString(final Node node) {
		return nodeObjectToString(node, true, false);
	}

	public static String nodeObjectToString(final Node node, boolean secure) {
		return nodeObjectToString(node, secure, false);
	}

	// advanced usage allowing to have it human-readable and including secrets e.g. in AuthnRequest
	public static String nodeObjectToString(final Node node, boolean secure, boolean prettyPrint) {
		try {
			if (node == null) {
				return null;
			}
			String xmlString;
			if (prettyPrint) {
				xmlString = SerializeSupport.prettyPrintXML(node);
			}
			else {
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				SerializeSupport.writeNode(node, out);
				xmlString = out.toString(StandardCharsets.UTF_8);
			}
			if (secure) {
				xmlString = OpenSamlUtil.replaceSensitiveData(xmlString);
			}

			return xmlString;
		}
		catch (Exception e) {
			log.error("Transforming Node to string failed on " + node, e);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T unmarshallDomElement(Element samlElement) throws UnmarshallingException {
		Unmarshaller unmarshaller = XMLObjectSupport.getUnmarshaller(samlElement);
		if (unmarshaller == null) {
			throw new UnmarshallingException(String.format("No unmarshaller for element: %s %s ",
					samlElement.getNamespaceURI(), samlElement.getLocalName()));
		}
		return (T)unmarshaller.unmarshall(samlElement);
	}

	public static <T extends SAMLObject> T extractSamlObjectFromEnvelope(Envelope envelope, Class<T> samlObjectClass) {
		SamlTracer.logSamlObject(">>>>> Incoming SOAP message", envelope);
		var xmlObjects = envelope.getBody().getUnknownXMLObjects();
		if (xmlObjects.size() != 1) {
			throw new TechnicalException(
					String.format("Unexpected request containing xmlObjects=%d != 1", xmlObjects.size()));

		}
		var xmlObject = xmlObjects.getFirst();
		if (!samlObjectClass.isAssignableFrom(xmlObject.getClass())) {
			throw new TechnicalException(String.format("Unexpected request of type=%s expected=%s",
					xmlObject.getClass().getName(), samlObjectClass.getName()));
		}
		return samlObjectClass.cast(xmlObject);
	}

	public static Envelope readEnvelope(InputStream inputStream) {
		var soapRequest = SamlIoUtil.getXmlObjectFromStream(inputStream, "SOAP");
		if (!(soapRequest instanceof Envelope envelope)) {
			throw new TechnicalException(
					String.format("Unexpected request of type=%s", soapRequest.getClass().getName()));
		}
		return envelope;
	}

	public static <T extends XMLObject> T findChildXmlObject(ElementExtensibleXMLObject baseObject, Class<T> xmlObjectClass) {
		var xmlObjects =
				baseObject.getUnknownXMLObjects().stream().filter(xmlObjectClass::isInstance).map(xmlObjectClass::cast).toList();
		if (xmlObjects.size() != 1) {
			throw new TechnicalException(String.format("Unexpected %s containing xmlObjects=%d != 1 of class=%s",
					baseObject.getClass().getSimpleName(), xmlObjects.size(), xmlObjectClass.getName()));

		}
		return xmlObjects.getFirst();
	}

	public static void sendSoap11Response(HttpServletResponse response, SAMLObject samlResponse) {
		try {
			var responseEnvelope = buildSoapEnvelope(samlResponse);
			var marshaller = XMLObjectSupport.getMarshaller(responseEnvelope);
			marshaller.marshall(responseEnvelope);
			SamlTracer.logSamlObject("<<<<< Outgoing SOAP message", responseEnvelope);
			sendEnvelope(response, responseEnvelope);
		}
		catch (MarshallingException|IOException ex) {
			throw new TechnicalException(String.format("Could not send response of type=%s ex=%s",
					samlResponse.getClass().getName(), ex.getMessage()), ex);
		}
	}

	private static void sendEnvelope(HttpServletResponse response, Envelope responseEnvelope) throws IOException {
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.TEXT_XML_VALUE);
		SamlIoUtil.writeXmlObjectToSteam(responseEnvelope, response.getOutputStream());
		response.flushBuffer();
	}

	public static Envelope buildSoapEnvelope(SAMLObject samlResponse) {
		var builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		var envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.<Envelope>ensureBuilder(
				Envelope.DEFAULT_ELEMENT_NAME);
		var bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory.<Body>ensureBuilder(Body.DEFAULT_ELEMENT_NAME);
		var responseEnvelope = envBuilder.buildObject();
		var body = bodyBuilder.buildObject();
		responseEnvelope.setBody(body);
		body.getUnknownXMLObjects().add(samlResponse);
		return responseEnvelope;
	}

	private static XMLSignatureFactory createSignatureFactory() {
		return XMLSignatureFactory.getInstance(MECHANISM_TYPE_DOM);
	}

	/**
	 * @param element
	 * @param signatureNode
	 * @param idAttributes list of pairs of (namespace, attributeName) for ID attributes to be registered for signature validation
	 * @param trustCredentials
	 * @return true if signature is valid and reference one of the allowed ID attributes
	 */
	public static boolean isSignatureValid(Element element, Node signatureNode, List<Pair<String, String>> idAttributes,
			List<Pair<String, String>> acceptedSignedElements, List<Credential> trustCredentials) {
		if (element == null) {
			log.info("No element");
			return false;
		}
		if (signatureNode == null) {
			log.info("No signature for element={}", element.getNodeName());
			return false;
		}
		// Element and Signature must be owned by same Document object (not unrelated):
		if (signatureNode.getOwnerDocument() != element.getOwnerDocument()) {
			log.info("Signature={} and element={} are not in the same document",
					signatureNode.getNodeName(), element.getNodeName());
			return false;
		}
		if (CollectionUtils.isEmpty(trustCredentials)) {
			log.info("Signature={} not validated for element={} without trust credentials",
					signatureNode.getNodeName(), element.getNodeName());
			return false;
		}

		registerIdAttributes(element.getOwnerDocument().getDocumentElement(), idAttributes, acceptedSignedElements);
		var expectedReferenceUris = getCandidateReferenceUris(element, idAttributes, acceptedSignedElements);
		if (expectedReferenceUris.isEmpty()) {
			log.info("Element={} has no usable ID attribute={} for signature reference validation of acceptedTypes={}",
					element.getNodeName(), idAttributes, acceptedSignedElements);
			return false;
		}

		var sigFactory = createSignatureFactory();
		XMLSignature validSignature = null;
		Credential validCredential = null;

		for (var trustCredential : trustCredentials) {
			validSignature = isSignatureValid(element, signatureNode, trustCredential, sigFactory);
			if (validSignature != null) {
				// Cryptographically valid signature found, no need to check other credentials
				// Signature object caches successful validation
				validCredential = trustCredential;
				break;
			}
		}
		if (validSignature == null) {
			if (log.isInfoEnabled()) {
				List<String> failedCredentials = trustCredentials.stream().map(SamlUtil::getKeyInfoHintFromCredential).toList();
				log.info("Signature not valid for element={} with credentials={}",
						element.getNodeName(), failedCredentials);
			}
			return false;
		}
		if (isSignatureReferenceValid(validSignature, expectedReferenceUris)) {
			if (log.isDebugEnabled()) {
				log.debug("Signature validation succeeded on element={} with credential={}",
						element.getNodeName(),SamlUtil.getKeyInfoHintFromCredential(validCredential));
			}
			return true;
		}
		if (log.isInfoEnabled()) {
			log.info("Signature is cryptographically valid  with credential={} but does not reference expected element={}",
					SamlUtil.getKeyInfoHintFromCredential(validCredential), element.getNodeName());
		}
		return false;
	}

	private static XMLSignature isSignatureValid(Element element, Node signatureNode, Credential trustCredential,
			XMLSignatureFactory sigFactory) {
		try {
			var credential = (BasicX509Credential) trustCredential;
			var publicKey = credential.getPublicKey();
			var valContext = new DOMValidateContext(publicKey, signatureNode);
			valContext.setProperty(SECURE_VALIDATION, Boolean.TRUE);
			var signature = sigFactory.unmarshalXMLSignature(valContext);
			if (signature.validate(valContext)) {
				return signature;
			}
		}
		catch (Exception ex) {
			if (log.isDebugEnabled()) {
				log.debug("Could not validate signature of element={} with credential={} : {} caused by {}",
						element.getNodeName(), SamlUtil.getKeyInfoHintFromCredential(trustCredential),
						ex.getMessage(), ExceptionUtil.getRootMessage(ex));
			}
		}
		return null;
	}

	private static void registerIdAttributes(Element element, List<Pair<String, String>> idAttributes,
			List<Pair<String, String>> acceptedSignedElements) {
		// nothing is ever added to the result list
		idAttributes.forEach(idAttribute ->
				applyOnElementAndChildren(element, idAttribute, acceptedSignedElements, SoapUtil::setIdAttribute,
						Collections.emptyList()));
	}

	private static List<String> getCandidateReferenceUris(Element element, List<Pair<String, String>> idAttributes,
			List<Pair<String, String>> acceptedSignedElements) {
		List<String> result = new ArrayList<>();
		idAttributes.forEach(idAttribute ->
				applyOnElementAndChildren(element, idAttribute, acceptedSignedElements, SoapUtil::getIdValueReference, result));
		return result;
	}

	private static boolean isSignatureReferenceValid(XMLSignature signature, List<String> candidateReferenceUris) {
		return signature.getSignedInfo().getReferences().stream()
				.map(URIReference::getURI)
				.anyMatch(candidateReferenceUris::contains);
	}

	private static String getIdReference(String id) {
		return "#" + id;
	}

	private static String getIdValueReference(Element element, Pair<String, String> idAttribute) {
		String result;
		if (idAttribute.getKey() != null) {
			result = element.getAttributeNS(idAttribute.getKey(), idAttribute.getValue());
		}
		else {
			result = element.getAttribute(idAttribute.getValue());
		}
		if (StringUtils.isNotEmpty(result)) {
			log.trace("Found ID attribute={} on element={} with value={}", idAttribute, element.getNodeName(), result);
			return getIdReference(result);
		}
		return null;
	}

	// returns null for applyOnElementAndChildren
	private static Void setIdAttribute(Element element, Pair<String, String> idAttribute) {
		if (idAttribute.getKey() != null) {
			if (element.hasAttributeNS(idAttribute.getKey(), idAttribute.getValue())) {
				log.trace("Set NS ID attribute={} on element={}", idAttribute, element.getNodeName());
				element.setIdAttributeNS(idAttribute.getKey(), idAttribute.getValue(), true);
			}
		}
		else if (element.hasAttribute(idAttribute.getValue())) {
			log.trace("Set ID attribute={} on element={}", idAttribute.getValue(), element.getNodeName());
			element.setIdAttribute(idAttribute.getValue(), true);
		}
		return null;
	}

	/**
	 * Apply a function on an element and its children recursively until a non-null result is returned.
	 */
	public static <T> void applyOnElementAndChildren(Element element, Pair<String, String> attribute,
			List<Pair<String, String>> acceptedElements,
			BiFunction<Element, Pair<String, String>, T> function, List<T> resultList) {
		if (element == null) {
			return;
		}
		if (acceptedElements.contains(Pair.of(element.getNamespaceURI(), element.getLocalName()))) {
			var result = function.apply(element, attribute);
			if (result != null) {
				resultList.add(result);
			}
		}
		else {
			log.trace("Ignoring element={} with namespace={} and localName={} as not in acceptedElements={}",
					element.getNodeName(), element.getNamespaceURI(), element.getLocalName(), acceptedElements);
		}
		var childNodes = element.getChildNodes();
		for (int item = 0; item < childNodes.getLength(); ++item) {
			var child = childNodes.item(item);
			if (child instanceof Element childElement) {
				applyOnElementAndChildren(childElement, attribute, acceptedElements, function, resultList);
			}
		}
	}

	/**
	 * @param element Base element to which the signature will be added
	 * @param idOfChildToSign ID of the child element to sign (must be an ID attribute, without leading #)
	 * @param signatureParameters signature parameters
	 * @param signingCredential Credential containing private key for signing and public key for KeyInfo.
	 * @return The Signature element that was added to the element.
	 */
	public static Element signElement(Element element, String idOfChildToSign,
			SignatureParameters signatureParameters, Credential signingCredential) {
		try {
			var sigFactory = createSignatureFactory();
			var digestMethod = sigFactory.newDigestMethod( signatureParameters.getDigestMethod(), null);
			var canonicalizationMethod = sigFactory.newCanonicalizationMethod(
					signatureParameters.getCanonicalizationAlgorithm(), (C14NMethodParameterSpec) null);
			var signatureMethod = sigFactory.newSignatureMethod(signatureParameters.getSignatureAlgorithm(), null);
			var transform = sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
			var idReference = getIdReference(idOfChildToSign);
			var ref = sigFactory.newReference(idReference, digestMethod, Collections.singletonList(transform), null, null);
			var signedInfo = sigFactory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));
			var keyInfoFactory = sigFactory.getKeyInfoFactory();
			var keyValue = keyInfoFactory.newKeyValue(signingCredential.getPublicKey());
			var keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));
			var signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
			var signContext = new DOMSignContext(signingCredential.getPrivateKey(), element);
			signature.sign(signContext);
			var signatureElements = element.getElementsByTagNameNS(SIGNATURE_NAMESPACE, SIGNATURE_NAME);
			if (signatureElements.getLength() != 1) {
				log.debug("Signatures found={} returning last one", signatureElements.getLength());
			}
			return (Element) signatureElements.item(signatureElements.getLength() - 1);
		}
		catch (Exception ex) {
			throw new TechnicalException(String.format("Could not sign element=%s ex=%s",
					element.getNodeName(), ex.getMessage()), ex);
		}
	}
}
