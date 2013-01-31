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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERUTF8String;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;

import com.novosec.pkix.asn1.cmp.ErrorMsgContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIFreeText;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;


/**
 * A very simple error message, no protection, or PBE protection
 * @author tomas
 * @version $Id: CmpErrorResponseMessage.java 12569 2011-09-14 10:21:15Z anatom $
 */
public class CmpErrorResponseMessage extends BaseCmpMessage implements IResponseMessage {

	private static final Logger log = Logger.getLogger(CmpErrorResponseMessage.class);
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

	/** The encoded response message */
    private byte[] responseMessage = null;
    private String failText = null;
    private FailInfo failInfo = null;
    private ResponseStatus status = null;
    private int requestId = 0;
	private int requestType = 23; // 23 is general error message

    public void setCertificate(Certificate cert) {
	}

	public void setCrl(final CRL crl) {
	}

	public void setIncludeCACert(final boolean incCACert) {
	}
	public void setCACert(final Certificate cACert) {
	}

	public byte[] getResponseMessage() throws IOException,
			CertificateEncodingException {
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
		return failText;
	}

	public boolean create() throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignRequestException, NotFoundException {
		final PKIHeader myPKIHeader = CmpMessageHelper.createPKIHeader(getSender(), getRecipient(), getSenderNonce(), getRecipientNonce(), getTransactionId());
		final PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(new DERInteger(2)); // 2 = rejection
		if (failInfo != null) {
			myPKIStatusInfo.setFailInfo(failInfo.getAsBitString());			
		}
		if (failText != null) {		
			myPKIStatusInfo.setStatusString(new PKIFreeText(new DERUTF8String(failText)));
		}
		PKIBody myPKIBody = null;
		log.debug("Create error message from requestType: "+requestType);
		if (requestType==0 || requestType==2) {
			myPKIBody = CmpMessageHelper.createCertRequestRejectBody(myPKIHeader, myPKIStatusInfo, requestId, requestType);
		} else {
			ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
			myPKIBody = new PKIBody(myErrorContent, 23); // 23 = error						
		}
		final PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		if ((getPbeDigestAlg() != null) && (getPbeMacAlg() != null) && (getPbeKeyId() != null) && (getPbeKey() != null) ) {
			responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, getPbeKeyId(), getPbeKey(), getPbeDigestAlg(), getPbeMacAlg(), getPbeIterationCount());
		} else {
			responseMessage = CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);			
		}
		return true;		
	}

	public boolean requireSignKeyInfo() {
		return false;
	}

	public void setSignKeyInfo(final Certificate cert, final PrivateKey key, final String provider) {
	}

	public void setSenderNonce(final String senderNonce) {
		super.setSenderNonce(senderNonce);
	}

	public void setRecipientNonce(final String recipientNonce) {
		super.setRecipientNonce(recipientNonce);
	}

	public void setTransactionId(final String transactionId) {
		super.setTransactionId(transactionId);
	}

	public void setRecipientKeyInfo(final byte[] recipientKeyInfo) {
	}

	public void setPreferredDigestAlg(final String digest) {
	}

	public void setRequestType(final int reqtype) {
		this.requestType = reqtype;
	}

	public void setRequestId(final int reqid) {
		this.requestId = reqid;
	}

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setProtectionParamsFromRequest(final IRequestMessage reqMsg) {
    }
}
