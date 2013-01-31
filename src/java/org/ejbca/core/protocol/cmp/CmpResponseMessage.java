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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;

import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.ErrorMsgContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIFreeText;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;

/**
 * CMP certificate response message
 * @author tomas
 * @version $Id: CmpResponseMessage.java 12569 2011-09-14 10:21:15Z anatom $
 */
public class CmpResponseMessage implements IResponseMessage {
	
	/**
	 * Determines if a de-serialized file is compatible with this class.
	 *
	 * Maintainers must change this value if and only if the new version
	 * of this class is not compatible with old versions. See Sun docs
	 * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
	 * /serialization/spec/version.doc.html> details. </a>
	 *
	 */
	private static final long serialVersionUID = 10003L;
	
	private static final Logger log = Logger.getLogger(CmpResponseMessage.class);
	
    /** The encoded response message */
    private byte[] responseMessage = null;

    /** status for the response */
	private ResponseStatus status = ResponseStatus.SUCCESS;
	
	/** Possible fail information in the response. Defaults to 'badRequest (2)'. */
	private FailInfo failInfo = FailInfo.BAD_REQUEST;
	
    /** Possible clear text error information in the response. Defaults to null. */
    private String failText = null;

    /**
	 * SenderNonce. This is base64 encoded bytes
	 */
	private String senderNonce = null;
	/**
	 * RecipientNonce in a response is the senderNonce from the request. This is base64 encoded bytes
	 */
	private String recipientNonce = null;
	
	/** transaction id */
	private String transactionId = null;
	
	/** Default digest algorithm for SCEP response message, can be overridden */
	private String digestAlg = CMSSignedGenerator.DIGEST_SHA1;
	/** The default provider is BC, if nothing else is specified when setting SignKeyInfo */
	private String provider = "BC";

	/** Certificate to be in certificate response message, not serialized */
	private transient Certificate cert = null;
	/** Certificate for the signer of the response message (CA) */
	private transient Certificate signCert = null;
	/** Private key used to sign the response message */
	private transient PrivateKey signKey = null;
	/** used to choose response body type */
	private transient int requestType;
	/** used to match request with response */
	private transient int requestId;
	
	private transient int pbeIterationCount = 1024;
	private transient String pbeDigestAlg = null;
	private transient String pbeMacAlg = null;
	private transient String pbeKeyId = null;
	private transient String pbeKey = null;
	
	public void setCertificate(final Certificate cert) {
		this.cert = cert;
	}
	
	public void setCrl(final CRL crl) {
		
	}
	
	public void setIncludeCACert(final boolean incCACert) {
	}
	public void setCACert(final Certificate cACert) {
	}
	
	public byte[] getResponseMessage() throws IOException, CertificateEncodingException {
        return responseMessage;
	}
	
	public void setStatus(final ResponseStatus status) {
        this.status = status;
	}
	
	public ResponseStatus getStatus() {
        return status;
	}
	
	public void setFailInfo(final FailInfo failInfo) {
        this.failInfo = failInfo;
	}
	
	public FailInfo getFailInfo() {
        return failInfo;
	}
	
    public void setFailText(final String failText) {
    	this.failText = failText;
    }

    public String getFailText() {
    	return this.failText;
    }

    public boolean create() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		boolean ret = false;
		// Some general stuff, common for all types of messages
		String issuer = null;
		String subject = null;
		if (cert != null) {
			final X509Certificate x509cert = (X509Certificate)cert;
			issuer = x509cert.getIssuerDN().getName();
			subject = x509cert.getSubjectDN().getName();
		} else if (signCert != null) {
			issuer = ((X509Certificate)signCert).getSubjectDN().getName();
			subject = "CN=fooSubject";
		} else {
			issuer = "CN=fooIssuer";
			subject = "CN=fooSubject";
		}
		
		final GeneralName issuerName = new GeneralName(new X509Name(issuer));
		final GeneralName subjectName = new GeneralName(new X509Name(subject));
		final PKIHeader myPKIHeader = CmpMessageHelper.createPKIHeader(issuerName, subjectName, senderNonce, recipientNonce, transactionId);

		try {
			if (status.equals(ResponseStatus.SUCCESS)) {
				if (cert != null) {
			    	if (log.isDebugEnabled()) {					
			    		log.debug("Creating a CertRepMessage 'accepted'");
			    	}
			    	final PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(new DERInteger(0)); // 0 = accepted
			    	final CertResponse myCertResponse = new CertResponse(new DERInteger(requestId), myPKIStatusInfo);
					
			    	final X509CertificateStructure struct = X509CertificateStructure.getInstance(new ASN1InputStream(new ByteArrayInputStream(cert.getEncoded())).readObject());
			    	final CertOrEncCert retCert = new CertOrEncCert(struct, 0);
			    	final CertifiedKeyPair myCertifiedKeyPair = new CertifiedKeyPair(retCert);
					myCertResponse.setCertifiedKeyPair(myCertifiedKeyPair);
					//myCertResponse.setRspInfo(new DEROctetString(new byte[] { 101, 111, 121 }));
					
					final CertRepMessage myCertRepMessage = new CertRepMessage(myCertResponse);
					
					int respType = requestType + 1; // 1 = intitialization response, 3 = certification response etc
			    	if (log.isDebugEnabled()) {
			    		log.debug("Creating response body of type " + respType);
			    	}
			    	final PKIBody myPKIBody = new PKIBody(myCertRepMessage, respType); 
			    	final PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
					
					if ( (pbeKeyId != null) && (pbeKey != null) && (pbeDigestAlg != null) && (pbeMacAlg != null) ) {
						responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, pbeKeyId, pbeKey, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
					} else {
						responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, (X509Certificate)signCert, signKey, digestAlg, provider);
					}
					ret = true;	
				}
			} else if (status.equals(ResponseStatus.FAILURE)) {
		    	if (log.isDebugEnabled()) {
		    		log.debug("Creating a CertRepMessage 'rejected'");
		    	}
				// Create a failure message
		    	final PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(new DERInteger(2)); // 2 = rejection
				myPKIStatusInfo.setFailInfo(failInfo.getAsBitString());
				if (failText != null) {
					myPKIStatusInfo.setStatusString(new PKIFreeText(new DERUTF8String(failText)));					
				}
				final PKIBody myPKIBody = CmpMessageHelper.createCertRequestRejectBody(myPKIHeader, myPKIStatusInfo, requestId, requestType);
				final PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
				
				if ( (pbeKeyId != null) && (pbeKey != null) && (pbeDigestAlg != null) && (pbeMacAlg != null) ) {
					responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, pbeKeyId, pbeKey, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
				} else {
					responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, (X509Certificate)signCert, signKey, digestAlg, provider);
				}
				ret = true;	
			} else {
		    	if (log.isDebugEnabled()) {
		    		log.debug("Creating a 'waiting' message?");
		    	}
				// Not supported, lets create a PKIError failure instead
				// Create a failure message
		    	final PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(new DERInteger(2)); // 2 = rejection
				myPKIStatusInfo.setFailInfo(failInfo.getAsBitString());
				if (failText != null) {
					myPKIStatusInfo.setStatusString(new PKIFreeText(new DERUTF8String(failText)));					
				}
				final ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
				final PKIBody myPKIBody = new PKIBody(myErrorContent, 23); // 23 = error
				final PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
				if ( (pbeKeyId != null) && (pbeKey != null) && (pbeDigestAlg != null) && (pbeMacAlg != null) ) {
					responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, pbeKeyId, pbeKey, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
				} else {
					responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, (X509Certificate)signCert, signKey, digestAlg, provider);
				}
				ret = true;	
			}
		} catch (CertificateEncodingException e) {
			log.error("Error creating CertRepMessage: ", e);
		} catch (InvalidKeyException e) {
			log.error("Error creating CertRepMessage: ", e);
		} catch (NoSuchProviderException e) {
			log.error("Error creating CertRepMessage: ", e);
		} catch (NoSuchAlgorithmException e) {
			log.error("Error creating CertRepMessage: ", e);
		} catch (SecurityException e) {
			log.error("Error creating CertRepMessage: ", e);
		} catch (SignatureException e) {
			log.error("Error creating CertRepMessage: ", e);
		}
		
		return ret;
	}
	
	public boolean requireSignKeyInfo() {
		return true;
	}
	
	public void setSignKeyInfo(final Certificate cert, final PrivateKey key, final String provider) {
		this.signCert = cert;
		this.signKey = key;
		if (provider != null) {
			this.provider = provider;
		}
	}
	
	public void setSenderNonce(final String senderNonce) {
		this.senderNonce = senderNonce;
	}
	
	public void setRecipientNonce(final String recipientNonce) {
		this.recipientNonce = recipientNonce;
	}
	
	public void setTransactionId(final String transactionId) {
		this.transactionId = transactionId;
	}
	
	public void setRecipientKeyInfo(final byte[] recipientKeyInfo) {
	}
	
	public void setPreferredDigestAlg(final String digest) {
		this.digestAlg = digest;
	}

    /** @see org.ejca.core.protocol.IResponseMessage
     */
	public void setRequestType(final int reqtype) {
		this.requestType = reqtype;
	}

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setRequestId(final int reqid) {
    	this.requestId = reqid;
    }
    
    @Override
	public void setProtectionParamsFromRequest(final IRequestMessage reqMsg) {
    	if (reqMsg instanceof ICrmfRequestMessage) {
    		final ICrmfRequestMessage crmf = (ICrmfRequestMessage) reqMsg;
			this.pbeIterationCount = crmf.getPbeIterationCount();
			this.pbeDigestAlg = crmf.getPbeDigestAlg();
			this.pbeMacAlg = crmf.getPbeMacAlg();
			this.pbeKeyId = crmf.getPbeKeyId();
			this.pbeKey = crmf.getPbeKey();
		}
    }

}
