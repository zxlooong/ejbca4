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

package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.mail.MessagingException;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.Test;

/**
 * Testing of CertStoreServlet
 * 
 * @author lars
 * @version $Id: CertStoreServletTest.java 12798 2011-10-03 13:38:29Z primelars $
 *
 */
public class CertStoreServletTest extends CaTestCase {
	private final static Logger log = Logger.getLogger(CertStoreServletTest.class);
	/**
	 * @throws MessagingException 
	 * @throws URISyntaxException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws MalformedURLException 
	 */
	@Test
	public void testIt() throws MalformedURLException, CertificateException, IOException, URISyntaxException, MessagingException {
		final CAInHierarchy ca1 = new CAInHierarchy("root", this);
		final CAInHierarchy ca1_1 = new CAInHierarchy("1 from root", this);
		ca1.subs.add(ca1_1);
		final CAInHierarchy ca2_1 = new CAInHierarchy("2 from root at"+new Date(), this);
		ca1.subs.add(ca2_1);
		final CAInHierarchy ca1_1_1 = new CAInHierarchy("1 from 1 from root", this);
		ca1_1.subs.add(ca1_1_1);
		final CAInHierarchy ca2_1_1 = new CAInHierarchy("2 from 1 from root at "+new Date(), this);
		ca1_1.subs.add(ca2_1_1);
		final CAInHierarchy ca3_1_1 = new CAInHierarchy("3 from 1 from root", this);
		ca1_1.subs.add(ca3_1_1);
		
		try {
			final Set<Integer> setOfSubjectKeyIDs = new HashSet<Integer>();
			final X509Certificate rootCert = ca1.createCA(setOfSubjectKeyIDs);
			log.info("The number of CAs created was "+setOfSubjectKeyIDs.size()+".");
			new CertFetchAndVerify().doIt( rootCert, setOfSubjectKeyIDs );
			assertEquals("All created CA certificates not found.", 0, setOfSubjectKeyIDs.size());
		}finally {
			ca1.deleteCA();
		}
	}
	@Test
	public void testDisplayPage() throws MalformedURLException, IOException, URISyntaxException {
		final String sURI = CertFetchAndVerify.getURL();
		log.debug("URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		Assert.assertTrue( "Fetching CRL with '"+sURI+"' is not working.", HttpURLConnection.HTTP_OK==connection.getResponseCode() );
		{
			final Map<String, List<String>> mheaders = connection.getHeaderFields();
			Assert.assertNotNull(mheaders);
			final StringWriter sw = new StringWriter();
			final PrintWriter pw = new PrintWriter(sw);
			pw.println("Header of page with valid links to certificates");
			for ( Entry<String, List<String>> e : mheaders.entrySet() ) {
				Assert.assertNotNull(e);
				Assert.assertNotNull(e.getValue());
				pw.println("\t"+e.getKey());
				for ( String s : e.getValue()) {
					pw.println("\t\t"+s);
				}
			}
			pw.close();
			log.debug(sw);
		}
		Assert.assertEquals("text/html;charset=UTF-8", connection.getContentType());
	}
}
