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
package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;

import javax.ejb.CreateException;
import javax.ejb.Local;

import org.ejbca.core.model.ca.store.CertificateInfo;

/**
 * Local interface for CertificateStoreSession.
 * @version $Id: CertificateStoreSessionLocal.java 15108 2012-07-06 12:25:48Z mikekushner $
 */
@Local
public interface CertificateStoreSessionLocal extends CertificateStoreSession {

    /**
     * Stores a certificate without checking authorization. This should be used from other methods where authorization to
     * the CA issuing the certificate has already been checked. For efficiency this method can then be used.
     * 
     * @param incert The certificate to be stored.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @return true if storage was successful.
     * @throws CreateException if the certificate can not be stored in the database
     */
	CertificateInfo findFirstCertificateInfo(String issuerDN, BigInteger serno);
}
