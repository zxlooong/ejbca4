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
package org.ejbca.util.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

/**
 * This trust manager may be used used by a client that does not bother to verify the TLS certificate chain of the server.
 * Could be us used when you are fetching things from the server that are signed by the server (like certificates).
 * The class must not be used on the server side.
 * 
 * Setting log level to trace makes it possible to see who is calling the methods of this class.
 * Could help when finding out which WS implementation that is being used. 
 *
 * @author Lars Silven PrimeKey
 * @version  $Id: X509TrustManagerAcceptAll.java 15310 2012-08-10 16:50:10Z primelars $
 *
 */
public class X509TrustManagerAcceptAll implements X509TrustManager {
	/**
	 * Log object.
	 */
	static private final Logger m_log = Logger.getLogger(X509TrustManagerAcceptAll.class);

	/**
	 */
	public X509TrustManagerAcceptAll() {
		if ( !m_log.isTraceEnabled() ) {
			return;
		}
		try {
			throw new Exception();
		} catch( Exception e ) {
			m_log.trace("X509TrustManagerAcceptAll constructor called", e);
		}
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		if ( !m_log.isTraceEnabled() ) {
			return;
		}
		try {
			throw new Exception();
		} catch( Exception e ) {
			m_log.trace("checkClientTrusted called", e);
		}
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		if ( !m_log.isTraceEnabled() ) {
			return;
		}
		try {
			throw new Exception();
		} catch( Exception e ) {
			m_log.trace("checkServerTrusted called", e);
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		if ( !m_log.isTraceEnabled() ) {
			return new X509Certificate[0];
		}
		try {
			throw new Exception();
		} catch( Exception e ) {
			m_log.trace("getAcceptedIssuers called", e);
		}
		return new X509Certificate[0];
	}

}
