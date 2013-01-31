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

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import com.novosec.pkix.asn1.cmp.PKIHeader;

/**
 * Base class for CMP message handlers that require RA mode secret verification.
 * 
 * This class contains common methods for extracting the RA authentication secret.
 * 
 * @version $Id: BaseCmpMessageHandler.java 13980 2012-02-06 23:24:28Z aveen4711 $
 */
public class BaseCmpMessageHandler {

	private static final Logger LOG = Logger.getLogger(BaseCmpMessageHandler.class);

    /** strings for error messages defined in internal resources */
	protected static final String CMP_ERRORADDUSER = "cmp.erroradduser";
	protected static final String CMP_ERRORGENERAL = "cmp.errorgeneral";
	
	protected static final int CMP_GET_EEP_FROM_KEYID  = -1;
	protected static final int CMP_GET_CP_FROM_KEYID   = -1;
	protected static final int CMP_GET_CA_FROM_EEP     = -1;
	protected static final int CMP_GET_CA_FROM_KEYID   = -2;

	protected Admin admin;
	protected CAAdminSession caAdminSession;
	protected EndEntityProfileSession endEntityProfileSession;
	protected CertificateProfileSession certificateProfileSession;

	protected BaseCmpMessageHandler() {
	}

	protected BaseCmpMessageHandler(final Admin admin, final CAAdminSession caAdminSession, final EndEntityProfileSession endEntityProfileSession, final CertificateProfileSession certificateProfileSession) {
		this.admin = admin;
		this.caAdminSession = caAdminSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.certificateProfileSession = certificateProfileSession;
	}

	/** @return SenderKeyId of in the header or null none was found. */
	protected String getSenderKeyId(final PKIHeader head) {
		String keyId = null;
		final DEROctetString os = head.getSenderKID();
		if (os != null) {
			try {
				keyId = new String(os.getOctets(), "UTF-8");
			} catch (UnsupportedEncodingException e2) {
				keyId = new String(os.getOctets());
				LOG.info("UTF-8 not available, using platform default encoding for keyId.");
			}
			if (keyId == null) {
				LOG.error("No KeyId contained in CMP request.");
			} else {
				if (!StringUtils.isAsciiPrintable(keyId)) {
					keyId = new String(Hex.encode(os.getOctets()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("keyId is not asciiPrintable, converting to hex: "+keyId);
					}					
				}
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("Found a sender keyId: "+keyId);
			}
		}
		return keyId;
	}

	/** @return the end entity profile id to use for a request based on the current configuration and keyId. */
	protected int getUsedEndEntityProfileId(final String keyId) throws NotFoundException {
		int ret = 0;
		String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
		if (StringUtils.equals(endEntityProfile, "KeyId")) {
            if(keyId != null) {
			    if (LOG.isDebugEnabled()) {
				    LOG.debug("Using End Entity Profile with same name as KeyId in request: "+keyId);
			    }
			    endEntityProfile = keyId;
            } else {
                LOG.error("Expecting the End Entity Profile ID to be specified in the KeyID parameter, but the KeyID parameter is 'null'");
            }
		} 
		ret = endEntityProfileSession.getEndEntityProfileId(admin, endEntityProfile);
		if (ret == 0) {
			final String msg = "No end entity profile found with name: "+endEntityProfile;
			LOG.info(msg);
			throw new NotFoundException(msg);
		}
		return ret;
	}

	/** @return the CA id to use for a request based on the current configuration, used end entity profile and keyId. */
	protected int getUsedCaId(final String keyId, int eeProfileId) throws NotFoundException {
		int ret = 0;
		final String caName = CmpConfiguration.getRACAName();
		if (StringUtils.equals(caName, "ProfileDefault")) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using default CA from End Entity Profile CA when adding users in RA mode.");
			}
			// get default CA id from end entity profile
			final EndEntityProfile eeProfile = endEntityProfileSession.getEndEntityProfile(admin, eeProfileId);
			ret = eeProfile.getDefaultCA();
			if (ret == -1) {
				LOG.error("No default CA id for end entity profile: "+eeProfileId);
			} else {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using CA with id: "+ret);
				}
			}
		} else if (StringUtils.equals(caName, "KeyId")) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using keyId as CA name when adding users in RA mode.");
			}
            if(keyId != null) {
			    // Use keyId as CA name
			    final CAInfo info = caAdminSession.getCAInfo(admin, keyId);
			    if (LOG.isDebugEnabled()) {
				    LOG.debug("Using CA: "+info.getName());
                }
                ret = info.getCAId();
            } else {
                LOG.error("Expecting the CA name to be specified in the KeyID parameter, but the KeyID parameter is 'null'");
			}																	
		} else {
			final CAInfo info = caAdminSession.getCAInfo(admin, caName);
			if (info == null) {
				LOG.info("No CA found matching caName: "+caName);
				throw new NotFoundException("CA with name '"+caName+"' not found");
			}
			ret = info.getCAId();					
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using fixed caName when adding users in RA mode: "+caName+"("+ret+")");
			}
		}
		return ret;
	}

	/** 
     * @return the certificate profile name to use for a request based on the current configuration and keyId. 
     */
	protected String getUsedCertProfileName(final String keyId, final int eeProfileId) throws NotFoundException {
        // Get the configured string, may be a profile name or 'KeyId' or 'ProfileDefault'
		String certificateProfile = CmpConfiguration.getRACertificateProfile();
        if (StringUtils.equals(certificateProfile, "KeyId")) {
            if(keyId != null) {
		        if (LOG.isDebugEnabled()) {
		            LOG.debug("Using Certificate Profile with same name as KeyId in request: " + keyId);
                }
                certificateProfile = keyId;
	        } else {
                LOG.error("Expecting the Certificate Profile name to be specified in the KeyID parameter, but the KeyID parameter is 'null'.");
                LOG.error("Certificate profile '" + certificateProfile + "' instead" );
            }
		}
		return certificateProfile;
	}
	/** @return the certificate profile to use for a request based on the current configuration and keyId. */
	protected int getUsedCertProfileId(final String certificateProfile) throws NotFoundException {
		final int ret = this.certificateProfileSession.getCertificateProfileId(this.admin, certificateProfile);					
		if (ret == 0) {
			final String msg = "No certificate profile found with name: "+certificateProfile;
			LOG.info(msg);
			throw new NotFoundException(msg);
		}
		return ret;
	}
}
