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

package org.ejbca.core.protocol.cmp.authentication;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Check the authentication of the PKIMessage by verifying the signature of the administrator who sent the message
 * 
 * @version $Id: EndEntityCertificateAuthenticationModule.java 13980 2012-02-06 23:24:28Z aveen4711 $
 *
 */
public class EndEntityCertificateAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger log = Logger.getLogger(EndEntityCertificateAuthenticationModule.class);
    private static final InternalResources intres = InternalResources.getInstance();
	
	private String authenticationParameterCAName;
	private String password;
	private String errorMessage;
    private Certificate extraCert;
	
	private Admin admin;
	private CAAdminSession caSession;
	private CertificateStoreSession certSession;
	private AuthorizationSession authSession;
	private EndEntityProfileSession eeProfileSession;
    private UserAdminSession eeAccessSession;

	public EndEntityCertificateAuthenticationModule(final String parameter) {
		this.authenticationParameterCAName = parameter;
		password = null;
		errorMessage = null;
		
		admin = null;
		caSession = null;
		certSession = null;
		authSession = null;
		eeProfileSession = null;
		eeAccessSession = null;
	}
	
	/**
	 * Sets the sessions needed to perform the verification.
	 * 
	 * @param adm
	 * @param caSession
	 * @param certSession
	 * @param authSession
	 * @param eeprofSession
	 */
	public void setSession(final Admin adm, final CAAdminSession caSession, final CertificateStoreSession certSession, 
			final AuthorizationSession authSession, final EndEntityProfileSession eeprofSession, final UserAdminSession eeaccessSession) {
		this.admin = adm;
		this.caSession = caSession;
		this.certSession = certSession;
		this.authSession = authSession;
		this.eeProfileSession = eeprofSession;
		this.eeAccessSession = eeaccessSession;
	}
	
	
	/**
	 * Returns the name of this authentication module as String
	 * 
	 * @return the name of this authentication module as String
	 */
	public String getName() {
		return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
	}
	
	/**
	 * Returns the password resulted from the verification process.
	 * 
	 * This password is set if verify() returns true.
	 * 
	 * @return The password as String. Null if the verification had failed.
	 */
	public String getAuthenticationString() {
		return this.password;
	}
	
	/**
	 * Get the error message resulted from the failure of the verification process.
	 * 
	 * The error message is set if verify() returns false.
	 * 
	 * @return The error message as String. Null if no error had ocured.
	 */
	public String getErrorMessage() {
		return this.errorMessage;
	}

    /**
     * Get the certificate that was attached to the CMP request in it's extraCert field.
     * 
     * @return The certificate that was attached to the CMP request in it's extraCert field 
     */
    public Certificate getExtraCert() {
        return extraCert;
    }

	/**
	 * Verifies the signature of 'msg'. msg should be signed by an authorized administrator in EJBCA and 
	 * the administrator's cerfificate should be attached in msg in the extraCert field.  
	 * 
     * When successful, the password is set to the randomly generated 16-digit String.
	 * When failed, the error message is set.
	 * 
	 * @param msg
	 * @return true if the message signature was verified successfully and false otherwise.
	 */
	public boolean verifyOrExtract(final PKIMessage msg, final String username) {
		
		//Check that there is a certificate in the extraCert field in msg
		final X509CertificateStructure extraCertStruct = msg.getExtraCert(0);
		if(extraCertStruct == null) {
			errorMessage = "There is no certificate in the extraCert field in the PKIMessage";
			log.info(errorMessage);
			return false;
		}
		
		//Read the extraCert and store it in a local variable
		try {
			extraCert = CertTools.getCertfromByteArray(extraCertStruct.getEncoded());
		} catch (CertificateException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			this.errorMessage = e.getLocalizedMessage();
		} catch (IOException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			this.errorMessage = e.getLocalizedMessage();
		}

        //Check that the certificate in the extraCert field exists in the DB
        final String fp = CertTools.getFingerprintAsString(extraCert);
        final Certificate dbcert = certSession.findCertificateByFingerprint(admin, fp);
        if(dbcert == null) {
            errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+". Fingerprint="+fp);
            }
            return false;
        }
        // Check that the certificate is not revoked
        CertificateInfo info = certSession.getCertificateInfo(admin, fp);
        if (info.getStatus() != SecConst.CERT_ACTIVE) {
            errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field is revoked.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+" Username="+info.getUsername());
            }
            return false;            
        }
        
        // Check that the certificate is valid
        X509Certificate cert = (X509Certificate) certSession.findCertificateByFingerprint(admin, fp);
        try {
            cert.checkValidity();
        } catch(Exception e) {
            errorMessage = "The certificate attached to the PKIMessage in the extraCert field in not valid";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+". Fingerprint="+fp);
                log.debug(e.getLocalizedMessage());
            }
        }
        
        CAInfo cainfo = null;
        try {
            // If client mode we will check if this certificate belongs to the user, and set the password of the request to this user's password
            // so it can later be used when issuing the certificate
            if (username != null) {
                if (!StringUtils.equals(username, info.getUsername())) {
                    errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"'.";
                    if(log.isDebugEnabled()) {
                        // Use a different debug message, as not to reveal too much information
                        final String debugMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"', but to user '"+info.getUsername()+"'.";
                        log.debug(debugMessage);
                    }
                    return false;                
                }
                if (log.isDebugEnabled()) {
                    log.debug("Extracting and setting password for user '"+username+"'.");
                }
                password = eeAccessSession.findUser(admin, username).getPassword();
            }
            //Check that the extraCert is issued by the right CA
            if (!StringUtils.equals("-", this.authenticationParameterCAName)) {
                cainfo = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
                //Check that the extraCert is given by the right CA
                if(!StringUtils.equals(CertTools.getIssuerDN(extraCert), cainfo.getSubjectDN())) {
                    errorMessage = "The End Entity certificate attached to the PKIMessage is not given by the CA \"" + this.authenticationParameterCAName + "\"";
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                }
            } else {
                cainfo = caSession.getCAInfo(this.admin, CertTools.getIssuerDN(extraCert).hashCode());
            }
        } catch (AuthorizationDeniedException e) {
            errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            return false;
        }            

        if (cainfo == null) {
            errorMessage = "CA '"+this.authenticationParameterCAName+"' does not exist.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            return false;
        }
        // Verify the signature of the client certificate as well, that it is really issued by this CA
        Certificate cacert = cainfo.getCertificateChain().iterator().next();
        try {
            extraCert.verify(cacert.getPublicKey(), "BC");
        } catch (Exception e) {
            errorMessage = "The End Entity certificate attached to the PKIMessage is not issued by the CA \"" + this.authenticationParameterCAName + "\"";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+": "+e.getLocalizedMessage());
            }
            return false;                
        }

        if(CmpConfiguration.getCheckAdminAuthorization()) {                    
            //Check that the request sender is an authorized administrator
            try {
                if(!isAuthorized(extraCert, msg, cainfo.getCAId())){
                    errorMessage = "\"" + CertTools.getSubjectDN(extraCert) + "\" is not an authorized administrator.";
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;           
                }
            } catch (NotFoundException e1) {
                errorMessage = e1.getLocalizedMessage();
                if(log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
            }
        }
        
        //Begin the verification process.
        //Verify the signature of msg using the public key of the certificate we found in the database
        try {
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
            sig.initVerify(extraCert.getPublicKey());
            sig.update(msg.getProtectedBytes());
            if (sig.verify(msg.getProtection().getBytes())) {
                if (password == null) {
                    // If not set earlier
                    password = genRandomPwd();
                }
				return true;
			}
		} catch (InvalidKeyException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (NoSuchAlgorithmException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (NoSuchProviderException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (SignatureException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		}
		return false;
	}

	/**
	 * Generated a random password of 16 digits.
	 * 
	 * @return a randomly generated password
	 */
    private String genRandomPwd() {
		final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
		return pwdgen.getNewPassword(12, 12);
    }
    
    /**
     * Checks if cert belongs to an administrator who is authorized to process the request.
     * 
     * @param cert
     * @param msg
     * @param caid
     * @return true if the administrator is authorized to process the request and false otherwise.
     * @throws NotFoundException
     */
    private boolean isAuthorized(final Certificate cert, final PKIMessage msg, final int caid) throws NotFoundException {
    	final CertificateInfo certInfo = certSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
    	final String username = certInfo.getUsername();
    	final Admin reqAdmin = new Admin(cert, username, CertTools.getEMailAddress(cert));    	
    	
        if (!authorizedToCA(reqAdmin, caid)) {
            errorMessage = intres.getLocalizedMessage("ra.errorauthca", Integer.valueOf(caid));
            log.info("Admin " + username + " is not authorized for CA " + caid);
            return false;
        }
        
        final int eeprofid = getUsedEndEntityProfileId(msg.getHeader().getSenderKID());
        final int tagnr = msg.getBody().getTagNo();
        if((tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST)) {
        
            if (!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.CREATE_RIGHTS)) {
            	errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
            	log.info(errorMessage);
                return false;
            }
            
        	if(!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.EDIT_RIGHTS)) {
        		errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
        		if(log.isDebugEnabled()) {
        			log.error(errorMessage);
        		}
                return false;
        	}
        	
        	if(!authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
        		errorMessage = "Administrator " + username + " is not authorized to create certificates.";
        		log.info(errorMessage);
                return false;
        	}
		} else if(tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
			
        	if(!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.REVOKE_RIGHTS)) {
        		errorMessage = "Administrator " + username + " is not authorized to revoke.";
        		log.info(errorMessage);
                return false;
        	}
			
        	if(!authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
        		errorMessage = "Administrator " + username + " is not authorized to revoke End Entities";
        		log.info(errorMessage);
                return false;
        	}
        	
        }
        
        return true;

    }
    
    /**
     * Checks whether admin is authorized to access the CA with ID caid
     * @param admin
     * @param caid
     * @return true of admin is authorized and false otherwize
     */
    private boolean authorizedToCA(Admin admin, int caid) {
        boolean returnval = false;
        returnval = authSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
        if (!returnval) {
        	errorMessage = "Admin " + admin.getUsername() + " not authorized to resource " + AccessRulesConstants.CAPREFIX + caid; 
            log.info(errorMessage);
        }
        return returnval;
    }
    
    /**
     * Checks whether admin is authorized to access the EndEntityProfile with the ID profileid
     * 
     * @param admin
     * @param profileid
     * @param rights
     * @return true if admin is authorized and false otherwise.
     */
    private boolean authorizedToEndEntityProfile(Admin admin, int profileid, String rights) {
        boolean returnval = false;
        if (profileid == SecConst.EMPTY_ENDENTITYPROFILE
                && (rights.equals(AccessRulesConstants.CREATE_RIGHTS) || rights.equals(AccessRulesConstants.EDIT_RIGHTS))) {
            if (authSession.isAuthorizedNoLog(admin, "/super_administrator")) {
                returnval = true;
            } else {
            	errorMessage = "Admin " + admin.getUsername() + " was not authorized to resource /super_administrator"; 
                log.info(errorMessage);
            }
        } else {
            returnval = authSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights)
                    && authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
        return returnval;
    }

    /**
     * Return the ID of EndEntityProfile that is used for CMP purposes. 
     * @param keyId
     * @return the ID of EndEntityProfile used for CMP purposes. 0 if no such EndEntityProfile exists. 
     * @throws NotFoundException
     */
	private int getUsedEndEntityProfileId(final DEROctetString keyId) throws NotFoundException {
		int ret = 0;
		String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
		if (StringUtils.equals(endEntityProfile, "KeyId") && (keyId != null)) {
			if (log.isDebugEnabled()) {
				log.debug("Using End Entity Profile with same name as KeyId in request: "+keyId);
			}
			endEntityProfile = keyId.toString();
		} 
		ret = eeProfileSession.getEndEntityProfileId(admin, endEntityProfile);
		if (ret == 0) {
			errorMessage = "No end entity profile found with name: "+endEntityProfile;
			log.info(errorMessage);
			throw new NotFoundException(errorMessage);
		}
		return ret;
	}
}
