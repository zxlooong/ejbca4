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
package org.ejbca.core.protocol.ws.common;

import org.bouncycastle.jce.PKCS10CertificationRequest;


/**
 * Class used to generate a PKCS10CertificationRequest from a 
 * org.ejbca.core.protocol.ws.common.ToeknPKCS10Request
 * 
 * @author Philip Vendil
 *
 * @version $Id: PKCS10Helper.java 8282 2009-11-09 14:57:21Z jeklund $
 */
public class PKCS10Helper {

	/**
	 * Retrieves the pkcs10 from the encoded data.
	 */
	public static PKCS10CertificationRequest getPKCS10(byte[] pkcs10Data) {
		return new PKCS10CertificationRequest(pkcs10Data);
	}
}
