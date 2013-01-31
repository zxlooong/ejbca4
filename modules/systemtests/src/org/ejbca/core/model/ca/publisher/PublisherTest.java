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

package org.ejbca.core.model.ca.publisher;

import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;



/**
 * Tests Publishers.
 *
 * @version $Id: PublisherTest.java 14156 2012-02-21 09:52:31Z primelars $
 */
public class PublisherTest extends TestCase {

	static final byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
			+ "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
			+ "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
			+ "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
			+ "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
			+ "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
			+ "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
			+ "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
			+ "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
			+ "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
			+ "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
			+ "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
			+ "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());

	static final byte[] testcacert = Base64.decode(("MIICLDCCAZWgAwIBAgIISDzEq64yCAcwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
			+ "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAxMTIw"
			+ "NDA5MzI1N1oXDTAzMTIwNDA5NDI1N1owLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD"
			+ "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
			+ "hwKBgQCnhOvkaj+9Qmt9ZseVn8Jhl6ewTrAOK3c9usxBhiGs+TalGjuAK37bbnbZ"
			+ "rlzCZpEsjSZYgXS++3NttiDbPzATkV/c33uIzBHjyk8/paOmTrkIux8hbIYMce+/"
			+ "WTYnAM3J41mSuDMy2yZxZ72Yntzqg4UUXiW+JQDkhGx8ZtcSSwIBEaNTMFEwDwYD"
			+ "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUy5k/bKQ6TtpTWhsPWFzafOFgLmswHwYD"
			+ "VR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmswDQYJKoZIhvcNAQEFBQADgYEA"
			+ "gHzQLoqLobU43lKvQCiZbYWEXHTf3AdzUd6aMOYOM80iKS9kgrMsnKjp61IFCZwr"
			+ "OcY1lOkpjADUTSqfVJWuF1z5k9c1bXnh5zu48LA2r2dlbHqG8twMQ+tPh1MYa3lV"
			+ "ugWhKqArGEawICRPUZJrLy/eDbCgVB4QT3rC7rOJOH0=").getBytes());

	static final byte[] testcrl = Base64.decode(("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
			+ "DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx"
			+ "MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
			+ "7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ"
			+ "Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
			+ "MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw"
			+ "MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
			+ "ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA"
			+ "kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
			+ "WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy"
			+ "MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
			+ "MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM"
			+ "45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
			+ "WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw"
			+ "OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
			+ "0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ"
			+ "SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());

	private final static String cloneName = "TESTCLONEDUMMYCUSTOM";
	private final static String orgName = "TESTDUMMYCUSTOM";
	private final static String newName = "TESTNEWDUMMYCUSTOM";

	private static final Logger log = Logger.getLogger(PublisherTest.class);

	private static final Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

	private final static Set<String> publisherNames = new HashSet<String>();

	private final CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
	private final ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
	private final PublisherSessionRemote publisherSession = InterfaceCache.getPublisherSession();

	/**
	 * Creates a new TestPublisher object.
	 *
	 * @param name name
	 */
	public PublisherTest(String name) {
		super(name);
	}

	@Override
	public void setUp() throws Exception {
		CryptoProviderTools.installBCProvider();
	}

	@Override
	public void tearDown() throws Exception {
		// do nothing
	}


	/**
	 * adds ldap publisher
	 * @throws AuthorizationDeniedException 
	 */
	public void test01AddLDAPPublisher() throws AuthorizationDeniedException {
		log.trace(">test01AddLDAPPublisher()");
		try {
			LdapPublisher publisher = new LdapPublisher();
			publisher.setHostnames("localhost");
			publisher.setDescription("Used in Junit Test, Remove this one");
			final String publisherName = "TESTLDAP";
			publisherNames.add(publisherName);
			this.publisherSession.addPublisher(admin, publisherName, publisher);
		} catch (PublisherExistsException pee) {
			final String m = "The name of the publisher does already exist for another publisher.";
			log.error(m, pee);
			assertTrue(m, false);
		}
		log.trace("<test01AddLDAPPublisher()");
	}

	/**
	 * adds ad publisher
	 * @throws AuthorizationDeniedException 
	 */
	public void test02AddADPublisher() throws AuthorizationDeniedException {
		log.trace(">test02AddADPublisher() ");
		try {
			ActiveDirectoryPublisher publisher = new ActiveDirectoryPublisher();
			publisher.setHostnames("localhost");
			publisher.setDescription("Used in Junit Test, Remove this one");
			final String publisherName = "TESTAD";
			publisherNames.add(publisherName);
			this.publisherSession.addPublisher(admin, publisherName, publisher);
		} catch (PublisherExistsException pee) {
			final String m = "The name of the publisher does already exist for another publisher.";
			log.error(m, pee);
			assertTrue(m, false);
		}
		log.trace("<test02AddADPublisher() ");
	}

	/**
	 * adds custom publisher
	 * @throws AuthorizationDeniedException 
	 */
	public void test03AddCustomPublisher() throws AuthorizationDeniedException {
		log.trace(">test03AddCustomPublisher()");
		try {
			CustomPublisherContainer publisher = new CustomPublisherContainer();
			publisher.setClassPath("org.ejbca.core.model.ca.publisher.DummyCustomPublisher");
			publisher.setDescription("Used in Junit Test, Remove this one");
			this.publisherSession.addPublisher(admin, orgName, publisher);
		} catch (PublisherExistsException pee) {
			final String m = "The name of the publisher does already exist for another publisher.";
			log.error(m, pee);
			assertTrue(m, false);
		}
		log.trace("<test03AddCustomPublisher()");
	}

	/**
	 * renames publisher
	 * @throws AuthorizationDeniedException 
	 */
	public void test04RenamePublisher() throws AuthorizationDeniedException {
		log.trace(">test04RenamePublisher()");
		try {
			publisherNames.add(newName);
			this.publisherSession.renamePublisher(admin, orgName, newName);
		} catch (PublisherExistsException pee) {
			final String m = "The new name of the publisher does already exist for another publisher.";
			log.error(m, pee);
			assertTrue(m, false);
		}
		log.trace("<test04RenamePublisher()");
	}

	/**
	 * clones publisher
	 */
	public void test05ClonePublisher() {
		log.trace(">test05ClonePublisher()");

		publisherNames.add(cloneName);
		this.publisherSession.clonePublisher(admin, newName, cloneName);

		log.trace("<test05ClonePublisher()");
	}

	/**
	 * edits publisher
	 * @throws AuthorizationDeniedException 
	 */
	public void test06EditPublisher() throws AuthorizationDeniedException {
		log.trace(">test06EditPublisher()");

		final BasePublisher publisher = this.publisherSession.getPublisher(admin, cloneName);
		publisher.setDescription(publisher.getDescription().toUpperCase());
		this.publisherSession.changePublisher(admin, cloneName, publisher);

		log.trace("<test06EditPublisher()");
	}

	/**
	 * stores a cert to the dummy publisher
	 * @throws CertificateException 
	 * @throws AuthorizationDeniedException 
	 */
	public void test07StoreCertToDummy() throws CertificateException, AuthorizationDeniedException {
		log.trace(">test07StoreCertToDummy()");
		final Certificate cert = CertTools.getCertfromByteArray(testcert);
		final ArrayList<Integer> publishers = new ArrayList<Integer>();
		publishers.add(Integer.valueOf(this.publisherSession.getPublisherId(admin, newName)));

		final boolean ret = this.publisherSession.storeCertificate(
				admin, publishers, cert, "test05", "foo123", null, null,
				SecConst.CERT_ACTIVE,
				SecConst.CERTTYPE_ENDENTITY,
				-1, RevokedCertInfo.NOT_REVOKED, "foo",
				SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
		assertTrue("Storing certificate to dummy publisher failed", ret);
		log.trace("<test07StoreCertToDummyr()");
	}

	/**
	 * stores a cert to the dummy publisher
	 * @throws CRLException 
	 * @throws AuthorizationDeniedException 
	 */
	public void test08storeCRLToDummy() throws CRLException, AuthorizationDeniedException {
		log.trace(">test08storeCRLToDummy()");
		final String issuerDn = CertTools.getIssuerDN(CertTools.getCRLfromByteArray(testcrl));
		final ArrayList<Integer> publishers = new ArrayList<Integer>();
		publishers.add(Integer.valueOf(this.publisherSession.getPublisherId(admin, newName)));
		final boolean ret = this.publisherSession.storeCRL(admin, publishers, testcrl, null, 1, issuerDn);
		assertTrue("Storing CRL to dummy publisher failed", ret);

		log.trace("<test08storeCRLToDummy()");
	}

	/**
	 * Test the VA publisher defines as a custom publisher.
	 * @throws AuthorizationDeniedException
	 * @throws PublisherConnectionException
	 * @throws CertificateException
	 */
	public void test14VAPublisherCustom() throws AuthorizationDeniedException, PublisherConnectionException, CertificateException {
		log.trace(">test14ExternalOCSPPublisher()");

		final String publisherName = "TESTEXTOCSP";
		try {
			CustomPublisherContainer publisher = new CustomPublisherContainer();
			publisher.setClassPath(ValidationAuthorityPublisher.class.getName());
			// We use the default EjbcaDS datasource here, because it probably exists during our junit test run
			final String jndiPrefix = this.configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX, "");
			final String jndiName = jndiPrefix + this.configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME, "EjbcaDS");
			log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
			publisher.setPropertyData("dataSource " + jndiName);
			publisher.setDescription("Used in Junit Test, Remove this one");
			publisherNames.add(publisherName);
			this.publisherSession.addPublisher(admin, publisherName, publisher);
		} catch (PublisherExistsException pee) {
			log.error(pee);
			assertTrue("Creating External OCSP Publisher failed", false);
		}
		final int id = this.publisherSession.getPublisherId(admin, publisherName);
		this.publisherSession.testConnection(admin, id);

		final Certificate cert = CertTools.getCertfromByteArray(testcert);

			ArrayList<Integer> publishers = new ArrayList<Integer>();
			publishers.add(Integer.valueOf(this.publisherSession.getPublisherId(admin, publisherName)));

			final boolean ret = this.publisherSession.storeCertificate(
					admin, publishers, cert, "test05", "foo123", null, null,
					SecConst.CERT_ACTIVE,
					SecConst.CERTTYPE_ENDENTITY,
					-1, RevokedCertInfo.NOT_REVOKED, "foo",
					SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
			assertTrue("Error storing certificate to external ocsp publisher", ret);

			this.publisherSession.revokeCertificate(
					admin, publishers, cert, "test05", null, null,
					SecConst.CERTTYPE_ENDENTITY,
					RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE,
					new Date().getTime(), "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime());

			log.trace("<test14ExternalOCSPPublisherCustom()");
	}

	private void storeCert(ArrayList<Integer> publishers, Certificate cert, long lastUpdate, int revokationReason, boolean doDelete) {
		final int certProfileID = SecConst.CERTPROFILE_FIXED_ENDUSER;
		final String tag = "foo";
		final String userName = "nytt 1";
		final String cafp = "CA fingerprint could be anything in this test.";
		final boolean ret = this.publisherSession.storeCertificate(admin, publishers, cert, userName, "foo123", null, cafp, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, revokationReason, tag, certProfileID, lastUpdate, null);
		assertTrue("Error storing certificate to external ocsp publisher", ret);

		final CertificateInfo info = this.certificateStoreSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
		if ( doDelete ) {
			assertNull("The certificate should not exist in the DB.", info);
			return;
		}
		assertNotNull("The certificate must be in DB.", info);
		assertEquals( SecConst.CERT_ACTIVE, info.getStatus() );
		assertEquals( revokationReason, info.getRevocationReason() );
		assertEquals( certProfileID, info.getCertificateProfileId() );
		assertEquals( tag, info.getTag() );
		assertEquals( lastUpdate, info.getUpdateTime().getTime() );
		assertEquals( userName, info.getUsername() );
		assertEquals( cafp, info.getCAFingerprint() );
	}
	private void revokeCert(ArrayList<Integer> publishers, Certificate cert, long lastUpdate) {
		final int certProfileID = 12345;
		final String tag = "foobar";
		final String userName = "nytt 2";
		final String cafp = "CA fingerprint could be anything in this test. Could also change value.";
		this.publisherSession.revokeCertificate(admin, publishers, cert, userName, null, cafp, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, new Date().getTime(), tag, certProfileID, lastUpdate);
		final CertificateInfo info = this.certificateStoreSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
		assertEquals( SecConst.CERT_REVOKED, info.getStatus() );
		assertEquals( certProfileID, info.getCertificateProfileId() );
		assertEquals( tag, info.getTag() );
		assertEquals( lastUpdate, info.getUpdateTime().getTime() );
		assertEquals( userName, info.getUsername() );
		assertEquals( cafp, info.getCAFingerprint() );
	}
	/**
	 * Test the VA publisher. It toggles "OnlyPublishRevoked" to see that no new certificates are published when set.
	 * @throws AuthorizationDeniedException
	 * @throws PublisherConnectionException
	 * @throws CertificateException
	 * @throws CRLException
	 */
	public void test15VAPublisher() throws AuthorizationDeniedException, PublisherConnectionException, CertificateException, CRLException {
		log.trace(">test15ExternalOCSPPublisher()");
		final String publisherName = "TESTEXTOCSP2";
		final ValidationAuthorityPublisher publisher = new ValidationAuthorityPublisher();
		{
			try {
				// We use the default EjbcaDS datasource here, because it probably exists during our junit test run
				final String jndiPrefix = this.configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX, "");
				final String jndiName = jndiPrefix + this.configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME, "EjbcaDS");
				log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
				publisher.setDataSource(jndiName);
				publisher.setDescription("Used in Junit Test, Remove this one");
				publisherNames.add(publisherName);
				this.publisherSession.addPublisher(admin, publisherName, publisher);
			} catch (PublisherExistsException pee) {
				log.error(pee);
				assertTrue("Creating External OCSP Publisher failed", false);
			}
		}
		final int id = this.publisherSession.getPublisherId(admin, publisherName);
		this.publisherSession.testConnection(admin, id);
		final Certificate cert = CertTools.getCertfromByteArray(testcert);

			final ArrayList<Integer> publishers = new ArrayList<Integer>();
			publishers.add(Integer.valueOf(this.publisherSession.getPublisherId(admin, publisherName)));

			long time = new Date().getTime();// check that certificate is published when added (no only published when revoked).
			storeCert(publishers, cert, time, RevokedCertInfo.NOT_REVOKED, false);
			time += 12345;// test that the revocation is published
			revokeCert(publishers, cert, time);

			publisher.setOnlyPublishRevoked(true);// activate only publish when revoked
			this.publisherSession.changePublisher(admin, publisherName, publisher);

			time += 12345;// check that the revoked certificate is removed from DB
			storeCert(publishers, cert, time, RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, true);
			time += 12345;// check that the certificate is not published when added
			storeCert(publishers, cert, time, RevokedCertInfo.NOT_REVOKED, true);
			time += 12345;// check that the certificate is published when revoked.
			revokeCert(publishers, cert, time);

			time += 12345; // just test that it is working a second time
			storeCert(publishers, cert, time, RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, true);
			time += 12345;
			storeCert(publishers, cert, time, RevokedCertInfo.NOT_REVOKED, true);

			final String issuerDn = CertTools.getIssuerDN(CertTools.getCRLfromByteArray(testcrl));
			// Test storing and updating CRLs as well
			this.publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, issuerDn);
			this.publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, issuerDn);

 		log.trace("<test15ExternalOCSPPublisher()");
	}

	/**
	 * removes all publishers
	 */
	public void test99removePublishers() throws Exception {
		log.trace(">test99removePublishers()");
		boolean ret = true;
		for( final String publisherName : publisherNames ) {
			try {
				this.publisherSession.removePublisher(admin, publisherName);
				log.debug("Publisher named '"+publisherName+"' removed.");
			} catch (Exception pee) {ret = false;}
		}
		assertTrue("Removing Publisher failed", ret);

		log.trace("<test99removePublishers()");
	}

} // TestPublisher
