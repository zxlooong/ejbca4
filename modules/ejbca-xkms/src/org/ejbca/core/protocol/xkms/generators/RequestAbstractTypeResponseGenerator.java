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

package org.ejbca.core.protocol.xkms.generators;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.crl.CrlSession;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.dn.DNFieldExtractor;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.ResultType;
import org.w3._2002._03.xkms_.StatusType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidityIntervalType;

/**
 * Help method that generates the most basic parts of a xkms message 
 * response
 * 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: RequestAbstractTypeResponseGenerator.java 11268 2011-01-26 23:02:58Z jeklund $
 */

public abstract class RequestAbstractTypeResponseGenerator extends BaseResponseGenerator{

    private static Logger log = Logger.getLogger(RequestAbstractTypeResponseGenerator.class);
    private static final InternalResources intres = InternalResources.getInstance();
    
    protected static final BigInteger SERVERRESPONSELIMIT = new BigInteger("30");

	protected RequestAbstractType req;
	protected ObjectFactory xkmsFactory = new ObjectFactory();
	protected org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	protected String resultMajor = null;
	protected String resultMinor = null;

	private CAAdminSession caAdminSession;
	private CertificateStoreSession certificateStoreSession;
	private CrlSession createCrlSession;

    public RequestAbstractTypeResponseGenerator(String remoteIP, RequestAbstractType req, CAAdminSession caAdminSession, CertificateStoreSession certificateStoreSession, CrlSession createCrlSession) {
        super(remoteIP);
        this.req = req;
        this.caAdminSession = caAdminSession;
        this.certificateStoreSession = certificateStoreSession;
        this.createCrlSession = createCrlSession;
    }

	/**
	 * Returns the generated response common data that should be sent back to the client
	 * @return the response
	 */
	protected void populateResponse(ResultType result, boolean requestVerifies){
		result.setService(genServiceValue());
		result.setId(genId());
		result.setRequestId(req.getId());					
		result.setOpaqueClientData(req.getOpaqueClientData());
		// Nonce is required for two phase commit	
		if(!requestVerifies){
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;			
		}
	}

	protected int getResponseLimit() {
		if(req.getResponseLimit() == null || req.getResponseLimit().compareTo(SERVERRESPONSELIMIT) >= 0){
			return SERVERRESPONSELIMIT.intValue();
		}
		return req.getResponseLimit().intValue();
	}

	private String genId() {
		String id = "";
		try {
			id = SernoGenerator.instance().getSerno().toString();
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("xkms.errorgenrespid"),e);			
		}
		return "_" + id;
	}

	// Should probably start with a protocol. See http://www.w3.org/TR/xkms2/#XKMS_2_0_Section_2_1 .
	private String genServiceValue() {
		return "http://" + WebConfiguration.getHostName() + ":" + WebConfiguration.getPublicHttpPort() + "/ejbca/xkms/xkms";
	}
	
    /**
     * Method used to set the result of the operation
     */	
    protected void setResult(ResultType result){
    	result.setResultMajor(resultMajor);
    	if(resultMinor != null){
    		result.setResultMinor(resultMinor);
    	}
    }
    
	/**
     * Method that returns the XKMS KeyUsage Constants that can be applied to the given 
     * X509Certiifcate
     * 
     * return List<String> of size 0 to 3 of XKMSConstants.KEYUSAGE_ constants.
     */
   protected List<String> getCertKeyUsageSpec(X509Certificate cert) {
	   ArrayList<String> retval = new ArrayList<String>();
	   
	   if(cert.getKeyUsage()[CertificateProfile.DATAENCIPHERMENT]){
		   retval.add(XKMSConstants.KEYUSAGE_ENCRYPTION);
	   }
	   if(cert.getKeyUsage()[CertificateProfile.DIGITALSIGNATURE] 
	      || cert.getKeyUsage()[CertificateProfile.KEYENCIPHERMENT]){
		   retval.add(XKMSConstants.KEYUSAGE_EXCHANGE);
	   }
	   if(XKMSConfig.signatureIsNonRep()){
		   if(cert.getKeyUsage()[CertificateProfile.NONREPUDIATION]){
			   retval.add(XKMSConstants.KEYUSAGE_SIGNATURE);
		   }
	   }else{
		     if(cert.getKeyUsage()[CertificateProfile.DIGITALSIGNATURE]){
		    	 retval.add(XKMSConstants.KEYUSAGE_SIGNATURE);
		     }		   
	   }
	   	   
	   return retval;
   }
   
   /**
    * Method that determines the UseKeyWith attribute from an X509Certificate
    * and the requested UseKeyWithAttributes
    */
   protected List<UseKeyWithType> genUseKeyWithAttributes(X509Certificate cert, List<UseKeyWithType> reqUsages) throws Exception{
	   ArrayList<UseKeyWithType> retval = new ArrayList<UseKeyWithType>();
	   
	   Iterator<UseKeyWithType> iter = reqUsages.iterator();
	   while(iter.hasNext()){
		   UseKeyWithType useKeyWithType =  iter.next();
		   DNFieldExtractor altNameExtractor = new DNFieldExtractor(CertTools.getSubjectAlternativeName(cert),DNFieldExtractor.TYPE_SUBJECTALTNAME);
		   String cn = CertTools.getPartFromDN(cert.getSubjectDN().toString(), "CN");
		   
		   
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMS)||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMSPROFILE) ||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLS)){
			    if(altNameExtractor.getField(DNFieldExtractor.URI, 0).startsWith(useKeyWithType.getIdentifier())){
			      retval.add(useKeyWithType);
			    }
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_SMIME)||
		  	  useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PGP)){
			    if(altNameExtractor.getField(DNFieldExtractor.RFC822NAME, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSHTTP)){			   
			    if(cn.startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   			   			   			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSSMTP)){
			    if(altNameExtractor.getField(DNFieldExtractor.DNSNAME, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_IPSEC)){
			    if(altNameExtractor.getField(DNFieldExtractor.IPADDRESS, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
			    if(CertTools.getSubjectDN(cert).equalsIgnoreCase(CertTools.stringToBCDNString(useKeyWithType.getIdentifier()))){
				      retval.add(useKeyWithType);
				}			   
		   } 
	   }
	   
	
	   return retval;
   }
   
	/**
    * Method adding supported response values specified
    * in the request
    * 
    * @param certificate to respond
    */
   protected KeyBindingAbstractType getResponseValues(KeyBindingAbstractType queryKeyBindingType, X509Certificate cert, boolean validateOrRevokeReq, boolean kRSSCall){
   	UnverifiedKeyBindingType retval = xkmsFactory.createUnverifiedKeyBindingType();    	
   	if(validateOrRevokeReq || kRSSCall){
   		retval = xkmsFactory.createKeyBindingType();
   		
   		((KeyBindingType) retval).setStatus(getStatus(cert,  kRSSCall));
   	}
   	    	

   	retval.setId("_" + cert.getSerialNumber().toString(16));             
   	retval.setValidityInterval(getValidityInterval(cert));

   	KeyInfoType keyInfoType = sigFactory.createKeyInfoType();

   	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_KEYNAME)){
   		String keyName = cert.getSubjectDN().toString();
   		keyInfoType.getContent().add(sigFactory.createKeyName(keyName));    		    		    	  	
   	}

   	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_KEYVALUE)){
   		if(cert.getPublicKey() instanceof RSAPublicKey){  
   			RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();      	
   			RSAKeyValueType rSAKeyValueType = sigFactory.createRSAKeyValueType();
   			rSAKeyValueType.setModulus(pubKey.getModulus().toByteArray());
   			rSAKeyValueType.setExponent(pubKey.getPublicExponent().toByteArray());
   			KeyValueType keyValue = sigFactory.createKeyValueType();
   			keyValue.getContent().add(sigFactory.createRSAKeyValue(rSAKeyValueType));
   			keyInfoType.getContent().add(sigFactory.createKeyValue(keyValue));    		    		    	  	
   		}else{
   			log.error(intres.getLocalizedMessage("xkms.onlyrsakeysupported"));   			
   			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
   			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
   		}
   	}

   	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CERT) || 
   			req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN) ||
   			req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CRL)){
   		    X509DataType x509DataType = sigFactory.createX509DataType();
   		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CERT) && !req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN)){
   			try {    					
   				x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
   			} catch (CertificateEncodingException e) {
   				log.error(intres.getLocalizedMessage("xkms.errordecodingcert"),e);   				
   				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
   				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
   			}
   		}
   		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN)){
   			int caid = CertTools.getIssuerDN(cert).hashCode();
   			try {
   				Iterator<Certificate> iter = caAdminSession.getCAInfo(pubAdmin, caid).getCertificateChain().iterator();
   				while(iter.hasNext()){
   					X509Certificate next = (X509Certificate) iter.next();
   					x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(next.getEncoded()));
   				}
   				x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
   			} catch (Exception e) {
   				log.error(intres.getLocalizedMessage("xkms.errorfetchinglastcrl"),e);   				
   				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
   				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
   			}
   		}
   		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CRL)){
   			byte[] crl = null;
   			try {
   				crl = createCrlSession.getLastCRL(pubAdmin, CertTools.getIssuerDN(cert), false);
   			} catch (Exception e) {
   				log.error(intres.getLocalizedMessage("xkms.errorfetchinglastcrl"),e);
   				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
   				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
   			}
   			x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509CRL(crl));
   		}    		
   		keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
   		
   	}
   	retval.setKeyInfo(keyInfoType);
   	retval.getKeyUsage().addAll(getCertKeyUsageSpec(cert));
		try {
			retval.getUseKeyWith().addAll(genUseKeyWithAttributes(cert, queryKeyBindingType.getUseKeyWith()));
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("xkms.errorextractingusekeyattr"),e);			
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
			
		}
   	
   	
   	return retval;
   }
   
	protected ValidityIntervalType getValidityInterval(X509Certificate cert) {
    	ValidityIntervalType valitityIntervalType = xkmsFactory.createValidityIntervalType();
		try {    	
		  GregorianCalendar notBeforeGregorianCalendar = new GregorianCalendar();
		  notBeforeGregorianCalendar.setTime(cert.getNotBefore());
    	  XMLGregorianCalendar notBeforeXMLGregorianCalendar = javax.xml.datatype.DatatypeFactory.newInstance().newXMLGregorianCalendar(notBeforeGregorianCalendar);
    	  notBeforeXMLGregorianCalendar.normalize();
    	  valitityIntervalType.setNotBefore(notBeforeXMLGregorianCalendar);
    	
		  GregorianCalendar notAfterGregorianCalendar = new GregorianCalendar();
		  notAfterGregorianCalendar.setTime(cert.getNotAfter());
    	  XMLGregorianCalendar notAfterXMLGregorianCalendar = javax.xml.datatype.DatatypeFactory.newInstance().newXMLGregorianCalendar(notAfterGregorianCalendar);
    	  notAfterXMLGregorianCalendar.normalize();
    	  valitityIntervalType.setNotOnOrAfter(notAfterXMLGregorianCalendar);    	
    	
		} catch (DatatypeConfigurationException e) {
			log.error(intres.getLocalizedMessage("xkms.errorsetvalidityinterval"),e);			
		}  	
    	
    	
		return valitityIntervalType;
	}
    

    /**
     * Method that checks the status of the certificate used
     * in a XKMS validate call. 
     * 
     * @param kRSSCall, regenerated certificate return all valid
     * @param cert
     */
    private StatusType getStatus(X509Certificate cert, boolean kRSSCall) {
        StatusType retval = xkmsFactory.createStatusType();
        
        if(kRSSCall){
        	retval.setStatusValue(XKMSConstants.STATUSVALUE_VALID);
        	retval.getValidReason().add(XKMSConstants.STATUSREASON_VALIDITYINTERVAL);
        	retval.getValidReason().add(XKMSConstants.STATUSREASON_ISSUERTRUST);
        	retval.getValidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        	retval.getValidReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);
        }else{
        	boolean allValid = true;
        	boolean inValidSet = false;

        	//Check validity
        	try{
        		cert.checkValidity( new Date());
        		retval.getValidReason().add(XKMSConstants.STATUSREASON_VALIDITYINTERVAL);
        	}catch(Exception e){
        		retval.getInvalidReason().add(XKMSConstants.STATUSREASON_VALIDITYINTERVAL);
        		allValid = false;
        		inValidSet = true;
        	}

        	// Check Issuer Trust
        	try{
        		int caid = CertTools.getIssuerDN(cert).hashCode();
        		CAInfo cAInfo = caAdminSession.getCAInfo(pubAdmin, caid);
        		if(cAInfo != null){
        			retval.getValidReason().add(XKMSConstants.STATUSREASON_ISSUERTRUST);

        			// Check signature	
        			try{
        				if(CertTools.verify(cert, cAInfo.getCertificateChain())){
        					retval.getValidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        				}else{
        					retval.getInvalidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        					allValid = false;
        					inValidSet = true;
        				}
        			}catch(Exception e){
        				retval.getInvalidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        				allValid = false;	
        				inValidSet = true;
        			}
        		}else{
        			retval.getInvalidReason().add(XKMSConstants.STATUSREASON_ISSUERTRUST);
        			retval.getIndeterminateReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        			allValid = false;
        			inValidSet = true;
        		}

        		// Check RevocationReason
        		CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        		if(status != CertificateStatus.NOT_AVAILABLE){
        			if(status.revocationReason == RevokedCertInfo.NOT_REVOKED){
        				retval.getValidReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);				  
        			}else{
        				retval.getInvalidReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);
        				allValid = false;
        				inValidSet = true;
        			}			  			
        		}else{
        			retval.getIndeterminateReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);
        			allValid = false;
        		}

        	} catch (ClassCastException e) {
        		log.error(intres.getLocalizedMessage("xkms.errorcreatesession"),e);
        		resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
        		resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
        	} 
        	if(allValid){
        		retval.setStatusValue(XKMSConstants.STATUSVALUE_VALID);
        	}else{
        		if(inValidSet){
        			retval.setStatusValue(XKMSConstants.STATUSVALUE_INVALID); 
        		}else{
        			retval.setStatusValue(XKMSConstants.STATUSVALUE_INDETERMINATE);
        		}
        	}
        }
		return retval;
	}
}
