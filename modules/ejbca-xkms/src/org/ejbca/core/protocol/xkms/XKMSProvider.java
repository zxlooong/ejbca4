/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.xkms;

import java.io.ByteArrayOutputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Provider;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.apache.xml.security.utils.XMLUtils;
import org.cesecore.core.ejb.ca.crl.CrlSessionLocal;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceResponse;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.generators.LocateResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.RecoverResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.RegisterResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.ReissueResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.RevokeResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.ValidateResponseGenerator;
import org.ejbca.core.protocol.xkms.generators.XKMSConfig;
import org.ejbca.util.CertTools;
import org.w3._2002._03.xkms_.LocateRequestType;
import org.w3._2002._03.xkms_.LocateResultType;
import org.w3._2002._03.xkms_.MessageAbstractType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * The XKMS Web Service in provider form
 * 
 * This is used as a workaround for the namespace prefix handling
 * in the JAX-WS
 * 
 * @author Philip Vendil 2006 dec 18
 * @version $Id: XKMSProvider.java 11634 2011-03-30 09:49:31Z jeklund $
 */
@Stateless
@ServiceMode(value=Service.Mode.PAYLOAD)
@WebServiceProvider(serviceName="XKMSService", targetNamespace = "http://www.w3.org/2002/03/xkms#wsdl", portName="XKMSPort", wsdlLocation="META-INF/wsdl/xkms.wsdl")
public class XKMSProvider implements Provider<Source> {
	@Resource
	private WebServiceContext wsContext;
	
	private static final Logger log = Logger.getLogger(XKMSProvider.class);
	
	private static final InternalResources intres = InternalResources.getInstance();
	
	protected Admin intAdmin = Admin.getInternalAdmin();
	
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	
    private JAXBContext jAXBContext = null;
    private Marshaller marshaller = null;
    private Unmarshaller unmarshaller = null;
    private DocumentBuilderFactory dbf = null;
    
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private AuthenticationSessionLocal authenticationSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private CrlSessionLocal crlSession;
    
	@PostConstruct
	public void postConstruct() {
    	try {
    		org.apache.xml.security.Init.init();
    		jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");    		
			marshaller = jAXBContext.createMarshaller();
	    	dbf = DocumentBuilderFactory.newInstance();
	    	dbf.setNamespaceAware(true);
	    	unmarshaller = jAXBContext.createUnmarshaller();
		} catch (JAXBException e) {
			log.error(intres.getLocalizedMessage("xkms.errorinitializinggenerator"),e);
		}
    }
	
	/**
	 * The main method performing the actual calls
	 */
	public Source invoke(Source request) {
		Source response = null;
		
		MessageContext msgContext = wsContext.getMessageContext();		
		HttpServletRequest httpreq = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		String remoteIP = httpreq.getRemoteAddr();
		
		Document requestDoc = null;
		try{
			DOMResult dom = new DOMResult();
			// The setproperty was suggested by Dai Tokunaga to get it working with Glassfish v2. It's not needed for JBoss though.
			//System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");  
			Transformer trans = TransformerFactory.newInstance().newTransformer();
			//System.setProperty("javax.xml.transform.TransformerFactory", "");  
			trans.transform(request, dom);
			requestDoc = (Document) dom.getNode();
		} catch (TransformerConfigurationException e) {
			log.error(intres.getLocalizedMessage("xkms.errorparsingdomreq"),e);
		} catch (TransformerFactoryConfigurationError e) {
			log.error(intres.getLocalizedMessage("xkms.errorparsingdomreq"),e);
		} catch (TransformerException e) {
			log.error(intres.getLocalizedMessage("xkms.errorparsingdomreq"),e);
		}
		
		boolean respMecSign = false;
		try {
			//JAXBElement jAXBRequest = (JAXBElement) unmarshaller.unmarshal(request);
			JAXBElement jAXBRequest = (JAXBElement) unmarshaller.unmarshal(requestDoc.cloneNode(true));
			JAXBElement jAXBResult = null;
			if(jAXBRequest.getValue() instanceof RequestAbstractType){
				respMecSign = ((RequestAbstractType)jAXBRequest.getValue()).getResponseMechanism().contains(XKMSConstants.RESPONSMEC_REQUESTSIGNATUREVALUE);
			}				
			if(jAXBRequest.getValue() instanceof ValidateRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = validate(remoteIP, (ValidateRequestType) jAXBRequest.getValue(), requestVerifies);
			}	
			if(jAXBRequest.getValue() instanceof LocateRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = locate(remoteIP, (LocateRequestType) jAXBRequest.getValue(), requestVerifies);
			}	
			if(jAXBRequest.getValue() instanceof RegisterRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = register(remoteIP, (RegisterRequestType) jAXBRequest.getValue(), requestVerifies, requestDoc);
			}	
			if(jAXBRequest.getValue() instanceof ReissueRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = reissue(remoteIP, (ReissueRequestType) jAXBRequest.getValue(), requestVerifies, requestDoc);
			}
			if(jAXBRequest.getValue() instanceof RecoverRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = recover(remoteIP, (RecoverRequestType) jAXBRequest.getValue(), requestVerifies, requestDoc);
			}
			
			if(jAXBRequest.getValue() instanceof RevokeRequestType ){
				boolean requestVerifies = verifyRequest(requestDoc);
				jAXBResult = revoke(remoteIP, (RevokeRequestType) jAXBRequest.getValue(), requestVerifies, requestDoc);
			}
			
			
			String responseId = ((MessageAbstractType) jAXBResult.getValue()).getId();			
			
			Document doc = dbf.newDocumentBuilder().newDocument();
			marshaller.marshal( jAXBResult, doc );
			doc = signResponseIfNeeded(doc, responseId, respMecSign, intAdmin);

		    		    
		    response = new DOMSource(doc);
			
					
		} catch (JAXBException e) {
		   log.error(intres.getLocalizedMessage("xkms.errorunmarshallingreq"),e);		   
		} catch (ParserConfigurationException e) {
		   log.error(intres.getLocalizedMessage("xkms.errorparsingresp"),e);
		}
		
		return response;
	}

	private JAXBElement validate(String remoteIP, ValidateRequestType value, boolean requestVerifies) {
		ValidateResponseGenerator gen = new ValidateResponseGenerator(remoteIP, value, certificateStoreSession, userAdminSession, crlSession, caAdminSession);
		JAXBElement<ValidateResultType> validateresult = xKMSObjectFactory.createValidateResult(gen.getResponse(requestVerifies));
		return validateresult;
	}
	
	private JAXBElement locate(String remoteIP, LocateRequestType value, boolean requestVerifies) {
		LocateResponseGenerator gen = new LocateResponseGenerator(remoteIP, value, certificateStoreSession, userAdminSession, crlSession, caAdminSession);
		JAXBElement<LocateResultType> locateresult = xKMSObjectFactory.createLocateResult(gen.getResponse(requestVerifies));
		return locateresult;
	}
	
	private JAXBElement register(String remoteIP, RegisterRequestType value, boolean requestVerifies, Document requestDoc) {
		RegisterResponseGenerator gen = new RegisterResponseGenerator(remoteIP, value,requestDoc, caAdminSession, authenticationSession, certificateStoreSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, userAdminSession, crlSession);
		JAXBElement<RegisterResultType> registerresult = xKMSObjectFactory.createRegisterResult(gen.getResponse(requestVerifies));
		return registerresult;
	}
	
	private JAXBElement reissue(String remoteIP, ReissueRequestType value, boolean requestVerifies, Document requestDoc) {
		ReissueResponseGenerator gen = new ReissueResponseGenerator(remoteIP, value,requestDoc, caAdminSession, authenticationSession, certificateStoreSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, userAdminSession, crlSession);
		JAXBElement<ReissueResultType> reissueresult = xKMSObjectFactory.createReissueResult(gen.getResponse(requestVerifies));
		return reissueresult;
	}
	
	private JAXBElement recover(String remoteIP, RecoverRequestType value, boolean requestVerifies, Document requestDoc) {
		RecoverResponseGenerator gen = new RecoverResponseGenerator(remoteIP, value,requestDoc, caAdminSession, authenticationSession, certificateStoreSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, userAdminSession, crlSession);
		JAXBElement<RecoverResultType> recoverresult = xKMSObjectFactory.createRecoverResult(gen.getResponse(requestVerifies));
		return recoverresult;
	}
	
	private JAXBElement revoke(String remoteIP, RevokeRequestType value, boolean requestVerifies, Document requestDoc) {
		RevokeResponseGenerator gen = new RevokeResponseGenerator(remoteIP, value,requestDoc, caAdminSession, authenticationSession, certificateStoreSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, userAdminSession, crlSession);
		JAXBElement<RevokeResultType> recoverresult = xKMSObjectFactory.createRevokeResult(gen.getResponse(requestVerifies));
		return recoverresult;
	}

	/**
	 * Method that verifies the content of the requests against the
	 * configured trusted CA.
	 * 
	 * @param kISSRequest if the caller is a kISSRequest
	 *
	 */
	private boolean verifyRequest(Document requestDoc) {		
			boolean signatureExists = false;

			Node xmlSig = null;
			NodeList nodeList = requestDoc.getChildNodes().item(0).getChildNodes();
			for(int i=0;i<nodeList.getLength();i++){
			  if(nodeList.item(i).getLocalName().equalsIgnoreCase("Signature")){
				  xmlSig = nodeList.item(i);
			  }
			}
			
			signatureExists = xmlSig != null;

			// Check that signature exists and if it's required
			boolean sigRequired = XKMSConfig.isSignedRequestRequired();

			if(sigRequired && !signatureExists){
				log.error(intres.getLocalizedMessage("xkms.recievedreqwithoutsig"));				
				return false;
			}else{
				if(signatureExists){

					try{																					
						org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element)xmlSig;        
						org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

						org.apache.xml.security.keys.KeyInfo keyInfo = xmlVerifySig.getKeyInfo();
						java.security.cert.X509Certificate verCert = keyInfo.getX509Certificate();


						// Check signature
						if(xmlVerifySig.checkSignatureValue(verCert)){ 							
							// Check that the issuer is among accepted issuers
							int cAId = CertTools.getIssuerDN(verCert).hashCode();

							Collection acceptedCAIds = XKMSConfig.getAcceptedCA(intAdmin, caAdminSession);
							if(!acceptedCAIds.contains(Integer.valueOf(cAId))){
								throw new Exception("Error XKMS request signature certificate isn't among the list of accepted CA certificates");
							}

							CAInfo cAInfo = caAdminSession.getCAInfo(intAdmin, cAId);
							Collection cACertChain = cAInfo.getCertificateChain();
							// Check issuer and validity						
							X509Certificate rootCert = null;
							Iterator iter = cACertChain.iterator();
							while(iter.hasNext()){
								X509Certificate cert = (X509Certificate) iter.next();
								if(cert.getIssuerDN().equals(cert.getSubjectDN())){
									rootCert = cert;
									break;
								}
							}

							if(rootCert == null){
								throw new CertPathValidatorException("Error Root CA cert not found in cACertChain"); 
							}

							List list = new ArrayList();
							list.add(verCert);
							list.add(cACertChain);


							CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
							CertStore store = CertStore.getInstance("Collection", ccsp);

							//validating path
							List certchain = new ArrayList();
							certchain.addAll(cACertChain);
							certchain.add(verCert);
							CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);

							Set trust = new HashSet();
							trust.add(new TrustAnchor(rootCert, null));

							CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
							PKIXParameters param = new PKIXParameters(trust);
							param.addCertStore(store);
							param.setDate(new Date());				        	
							param.setRevocationEnabled(false);

							cpv.validate(cp, param); 

							// Check revocation status
							boolean revoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(verCert), verCert.getSerialNumber());
							if (revoked) {
								return false;
							}
						}else{
							log.error(intres.getLocalizedMessage("xkms.errorreqsigdoesntverify"));							
							return false;
						}
					}catch(Exception e){
						log.error(intres.getLocalizedMessage("xkms.errorwhenverifyingreq"));						
						return false;
					}
				}
			}

		return true;
	}
	
	/**
	 * Method that checks if signing is required by
	 * checking the service configuration and the request,
	 * It then signs the request, othervise it isn't
	 * @param admin 
	 * @return the document signed or null of the signature failed;
	 */
	private Document signResponseIfNeeded(Document result, String id, boolean respMecSign, Admin admin){
		Document retval = result;

		if(XKMSConfig.alwaysSignResponses() || (XKMSConfig.acceptSignRequests() && respMecSign)){
			try {
				if (log.isDebugEnabled()) {
			        // Output what we are trying to process..
			        ByteArrayOutputStream baos = new ByteArrayOutputStream();
			        XMLUtils.outputDOMc14nWithComments(result, baos);
			        log.debug("(Unsigned) signResponseIfNeeded XMLUtils.outputDOMc14nWithComments: " + baos.toString());
			        //javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
			        //result = db.parse(baos.toString());

				}

				XKMSCAServiceRequest cAReq = new XKMSCAServiceRequest(result, id,true,false);

				XKMSCAServiceResponse resp = (XKMSCAServiceResponse) caAdminSession.extendedService(admin, XKMSConfig.cAIdUsedForSigning(admin, caAdminSession), cAReq);

				retval = resp.getSignedDocument();
				if (log.isDebugEnabled()) {
			        // Output what we just processed..
			        ByteArrayOutputStream baos = new ByteArrayOutputStream();
			        XMLUtils.outputDOMc14nWithComments(retval, baos);
			        log.debug("(Signed) signResponseIfNeeded XMLUtils.outputDOMc14nWithComments: " + baos.toString());
				}
			} catch (Exception e) {
				log.error(intres.getLocalizedMessage("xkms.errorgenrespsig"), e);				
				retval = null;
			}
		}

		return retval;
    }           
}
