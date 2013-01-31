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

package org.ejbca.core.ejb.ca.crl;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.cesecore.core.ejb.ca.crl.CrlSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.ui.web.protocol.RFC4387URL;
import org.ejbca.util.InterfaceCache;

/**
 * This class is needed because a junit test class can not have a reference to an enum.
 * Classes having enum references will produce extra classes with '$1' appended to the class name.
 * The junit framework can't stand these extra classes if they have "Test" in the name.
 * 
 * @author Lars Silven PrimeKey
 * @version $Id: ValidationAuthorityTst.java 15003 2012-06-17 23:55:15Z primelars $
 */
class ValidationAuthorityTst {
	private final static Logger log = Logger.getLogger(ValidationAuthorityTst.class);
	private final static Admin admin =  new Admin(Admin.TYPE_CACOMMANDLINE_USER);
	private final static ConfigurationSessionRemote configuration = InterfaceCache.getConfigurationSession();
	static String testCRLStore(CA ca, CrlSessionRemote createCrlSession, String port) throws Exception {
        // Before running this we need to make sure the certificate cache is refreshed, there may be a cache delay which is acceptable in real life, 
        // but not when running JUnit tests  
		final String sURI = "http://localhost:" + port + "/crls/search.cgi?reloadcache=true";
		log.debug("Reload cache URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		log.debug("reloadcache returned code: "+connection.getResponseCode());
		// Now on to the actual tests, with fresh caches
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		testCRLStore( pw, RFC4387URL.sKIDHash, false, ca, createCrlSession, port );
		testCRLStore( pw, RFC4387URL.iHash, false, ca, createCrlSession, port );
		testCRLStore( pw, RFC4387URL.sKIDHash, true, ca, createCrlSession, port );
		testCRLStore( pw, RFC4387URL.iHash, true, ca, createCrlSession, port );
		pw.flush();
		final String problems = sw.toString();
		if ( !problems.isEmpty() ) {
			return problems; // some tests has failed
		}
		return null; // everything OK
	}
	private static void testCRLStore( PrintWriter pw, RFC4387URL urlType, boolean isDelta, CA ca, CrlSessionRemote createCrlSession, String port) throws Exception {
		final X509Certificate caCert = (X509Certificate)ca.getCACertificate();
		final HashID id;
		final boolean aliasTest;
		switch( urlType ) {
		case sKIDHash:
			id = HashID.getFromKeyID(caCert);
			aliasTest = true;
			break;
		case iHash:
			id = HashID.getFromSubjectDN(caCert);
			aliasTest = false;
			break;
		default:
			throw new Error("this should never happen");
		}
		final String sBaseURI = "http://localhost:" + port + "/crls/search.cgi";
		final String caSubjectDN = ca.getCAInfo().getSubjectDN();
		{
			final String sURI = urlType.appendQueryToURL(sBaseURI, id, isDelta);
			testURI( pw, createCrlSession, sURI, caSubjectDN, isDelta );
		}
		if ( !aliasTest ) {
			return;
		}
		final String alias = "alias";
		final String key = "va.sKIDHash.alias."+alias;
		final String value = id.b64url;
		configuration.updateProperty(key, value);
		final String sURI = sBaseURI + "?alias="+alias+(isDelta ? "&delta=" : "");
		testURI( pw, createCrlSession, sURI, caSubjectDN, isDelta );
	}
	private static void testURI( PrintWriter pw, CrlSessionRemote createCrlSession, String sURI, String caSubjectDN, boolean isDelta ) throws Exception {
		log.debug("URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		final int responseCode = connection.getResponseCode();
		if ( HttpURLConnection.HTTP_OK!=responseCode ) {
			if ( responseCode==HttpURLConnection.HTTP_NOT_FOUND ) {
				pw.println("crlstore test not done because crlstore not enabled. To run the test set 'crlstore.enabled' in ./conf/crl.properties and then 'ant deploy' and restart appserver.");
				return;
			}
			pw.println(" Fetching CRL with '"+sURI+"' is not working. responseCode="+connection.getResponseCode());
			return;
		}

		final byte fromBean[] = createCrlSession.getLastCRL(admin, caSubjectDN, isDelta);
		final byte fromURL[] = new byte[connection.getContentLength()];
		connection.getInputStream().read(fromURL);
		if ( !Arrays.areEqual(fromBean, fromURL) ) {
			pw.println(" CRL from URL and bean are not equal for '"+sURI+"'.");
		}
	}
}
