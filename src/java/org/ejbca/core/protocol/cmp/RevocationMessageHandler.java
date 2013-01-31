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

import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.RevDetails;
import com.novosec.pkix.asn1.cmp.RevReqContent;
import com.novosec.pkix.asn1.crmf.CertTemplate;

/**
 * Message handler for the CMP revocation request messages
 * @author tomas
 * @version $Id: RevocationMessageHandler.java 13980 2012-02-06 23:24:28Z aveen4711 $
 */
public class RevocationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(RevocationMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
	
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	
	private UserAdminSession userAdminSession;
	private CertificateStoreSession certificateStoreSession;
	private AuthorizationSession authorizationSession;
	private CaSession caSession;
	
	public RevocationMessageHandler(final Admin admin, final CaSession casession, final CertificateStoreSession certificateStoreSession, final UserAdminSession userAdminSession, final CAAdminSession caAdminSession, final EndEntityProfileSession endEntityProfileSession, final CertificateProfileSession certificateProfileSession, final AuthorizationSession authSession) {
		super(admin, caAdminSession, endEntityProfileSession, certificateProfileSession);
		responseProtection = CmpConfiguration.getResponseProtection();
		
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		this.caSession = casession;
		this.userAdminSession = userAdminSession;
		this.certificateStoreSession = certificateStoreSession;
		this.authorizationSession = authSession;
	}
	public IResponseMessage handleMessage(final BaseCmpMessage msg) {
		LOG.trace(">handleMessage");
		IResponseMessage resp = null;
		
		CA ca = null;
		try {
			ca = caSession.getCA(admin, msg.getHeader().getRecipient().getName().toString().hashCode());
        } catch (CADoesntExistsException e) {
            final String errMsg = "CA with DN '" + msg.getHeader().getRecipient().getName().toString() + "' is unknown";
            return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, errMsg);
        }
		
		// if version == 1 it is cmp1999 and we should not return a message back
		// Try to find a HMAC/SHA1 protection key
		String owfAlg = null;
		String macAlg = null;
		final int iterationCount = 1024;
		String cmpRaAuthSecret = null;
		final String keyId = getSenderKeyId(msg.getHeader());
		ResponseStatus status = ResponseStatus.FAILURE;
		FailInfo failInfo = FailInfo.BAD_MESSAGE_CHECK;
		String failText = null;
			
		//Verify the authenticity of the message
		final VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(ca.getCAInfo(), admin, caAdminSession, userAdminSession, certificateStoreSession, authorizationSession, endEntityProfileSession);
		ICMPAuthenticationModule authenticationModule = null;
		if(messageVerifyer.verify(msg.getMessage(), null)) {
			authenticationModule = messageVerifyer.getUsedAuthenticationModule();
		}
		if(authenticationModule == null) {
			String errMsg = "";
			if(messageVerifyer.getErrorMessage() != null) {
				errMsg = messageVerifyer.getErrorMessage();
			} else {
				errMsg = "Unrecognized authentication modules";
			}
			LOG.error(errMsg);
			return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		} else {
			if(authenticationModule instanceof HMACAuthenticationModule) {
				final HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
				owfAlg = hmacmodule.getCmpPbeVerifyer().getOwfOid();
				macAlg = hmacmodule.getCmpPbeVerifyer().getMacOid();
			}
		}
			
		cmpRaAuthSecret = authenticationModule.getAuthenticationString();
		if (cmpRaAuthSecret != null) {
			// If authentication was correct, we will now try to find the certificate to revoke
			final PKIMessage pkimsg = msg.getMessage();
			final PKIBody body = pkimsg.getBody();
			final RevReqContent rr = body.getRr();
			final RevDetails rd = rr.getRevDetails(0);
			final CertTemplate ct = rd.getCertDetails();
			final DERInteger serno = ct.getSerialNumber();
			final X509Name issuer = ct.getIssuer();
			// Get the revocation reason. 
			// For CMPv1 this can be a simple DERBitString or it can be a requested CRL Entry Extension
			// If there exists CRL Entry Extensions we will use that, because it's the only thing allowed in CMPv2
			int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
			final DERBitString reasonbits = rd.getRevocationReason();
			if (reasonbits != null) {
				reason = CertTools.bitStringToRevokedCertInfo(reasonbits);
				if (LOG.isDebugEnabled()) {
					LOG.debug("CMPv1 revocation reason: "+reason);
				}
			} else {
				if (LOG.isDebugEnabled()) {
					LOG.debug("CMPv1 revocation reason is null");
				}
			}
			final X509Extensions crlExt = rd.getCrlEntryDetails();
			if (crlExt != null) {
				X509Extension ext = crlExt.getExtension(X509Extensions.ReasonCode);
				if (ext != null) {
					try {
						final ASN1InputStream ai = new ASN1InputStream(ext.getValue().getOctets());
						final DERObject obj = ai.readObject();
						final DEREnumerated crlreason = DEREnumerated.getInstance(obj);
						// RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE are the same integer values as the CRL reason extension code
						reason = crlreason.getValue().intValue();
						if (LOG.isDebugEnabled()) {
							LOG.debug("CRLReason extension: "+reason);
						}
					} catch (IOException e) {
						LOG.info("Exception parsin CRL reason extension: ", e);
					}
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("No CRL reason code extension present.");
					}
				}
			} else {
				if (LOG.isDebugEnabled()) {
					LOG.debug("No CRL entry extensions present");
				}
			}
				
			if ( (serno != null) && (issuer != null) ) {
				final String iMsg = INTRES.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
				LOG.info(iMsg);
				try {
					userAdminSession.revokeCert(admin, serno.getValue(), issuer.toString(), reason);
					status = ResponseStatus.SUCCESS;
				} catch (AuthorizationDeniedException e) {
					failInfo = FailInfo.NOT_AUTHORIZED;
					final String errMsg = INTRES.getLocalizedMessage("cmp.errornotauthrevoke", issuer.toString(), serno.getValue().toString(16));
					failText = errMsg; 
					LOG.error(failText);
				} catch (FinderException e) {
					failInfo = FailInfo.BAD_CERTIFICATE_ID;
					final String errMsg = INTRES.getLocalizedMessage("cmp.errorcertnofound", issuer.toString(), serno.getValue().toString(16));
					failText = errMsg; 
					LOG.error(failText);
				} catch (WaitingForApprovalException e) {
					status = ResponseStatus.GRANTED_WITH_MODS;
				} catch (ApprovalException e) {
					failInfo = FailInfo.BAD_REQUEST;
					final String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrequested");
					failText = errMsg; 
					LOG.error(failText);
				} catch (AlreadyRevokedException e) {
					failInfo = FailInfo.BAD_REQUEST;
					final String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrevoked");
					failText = errMsg; 
					LOG.error(failText);
				}
			} else {
				failInfo = FailInfo.BAD_CERTIFICATE_ID;
				final String errMsg = INTRES.getLocalizedMessage("cmp.errormissingissuerrevoke", issuer.toString(), serno.getValue().toString(16));
				failText = errMsg; 
				LOG.error(failText);
			}
		} else {
			final String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage");
			LOG.error(errMsg);
			failText = errMsg;
			if (authenticationModule.getErrorMessage() != null) {
				failText = authenticationModule.getErrorMessage();
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Creating a PKI revocation message response");
		}
		final CmpRevokeResponseMessage rresp = new CmpRevokeResponseMessage();
		rresp.setRecipientNonce(msg.getSenderNonce());
		rresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
		rresp.setSender(msg.getRecipient());
		rresp.setRecipient(msg.getSender());
		rresp.setTransactionId(msg.getTransactionId());
		rresp.setFailInfo(failInfo);
		rresp.setFailText(failText);
		rresp.setStatus(status);
		// Set all protection parameters
		if (LOG.isDebugEnabled()) {
			LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
		}
		if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
			rresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
	    } else {
	    	try {
	    		rresp.setSignKeyInfo(ca.getCACertificate(), ca.getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), ca.getCAToken().getProvider());
	    	} catch(IllegalKeyStoreException e) {
	    		LOG.error(e.getLocalizedMessage());
	    	} catch(CATokenOfflineException e) {
	    		LOG.error(e.getLocalizedMessage());
	    	}
	    }
		resp = rresp;
		try {
			resp.create();
		} catch (InvalidKeyException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		} catch (NoSuchAlgorithmException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		} catch (NoSuchProviderException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		} catch (SignRequestException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		} catch (NotFoundException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		} catch (IOException e) {
			String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
			LOG.error(errMsg, e);			
		}
		
		return resp;
	}
}
