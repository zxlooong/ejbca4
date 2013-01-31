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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.cesecore.core.ejb.authorization.AdminEntitySessionRemote;
import org.cesecore.core.ejb.authorization.AdminGroupSessionRemote;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.ConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.authentication.EndEntityCertificateAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * This will test the different cmp authentication modules.
 * 
 * @version $Id: AuthenticationModulesTest.java 14024 2012-02-09 00:07:29Z aveen4711 $
 *
 */
public class AuthenticationModulesTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(AuthenticationModulesTest.class);
	
	private String username;
	private String userDN;
	private String issuerDN;
	private byte[] nonce;
	private byte[] transid;
	private int caid;
	private Certificate cacert;
	
    private Admin admin;
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    private ConfigurationSessionRemote confSession = InterfaceCache.getConfigurationSession();
    private CertificateStoreSession certSession = InterfaceCache.getCertificateStoreSession();
    private AuthorizationSession authorizationSession = InterfaceCache.getAuthorizationSession();
    private AdminGroupSessionRemote adminGroupSession = InterfaceCache.getAdminGroupSession();
    private AdminEntitySessionRemote adminEntitySession = InterfaceCache.getAdminEntitySession();
    private CertificateStoreSessionRemote certStoreSession = InterfaceCache.getCertificateStoreSession();
    
	public AuthenticationModulesTest(String arg0) {
		super(arg0);

		admin = new Admin(Admin.TYPE_RA_USER);
		
		username = "authModuleTestUser";
	    userDN = "CN="+username+",O=PrimeKey Solutions AB,C=SE,UID=foo123";
	    issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
	    nonce = CmpMessageHelper.createSenderNonce();
	    transid = CmpMessageHelper.createSenderNonce();

        CryptoProviderTools.installBCProvider();
        setCAID();
        setCaCert();
        
		confSession.backupConfiguration();
		
		updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");


	}

	public void test01HMACModule() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidAlgorithmParameterException {
		
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caAdminSession.getCAInfo(admin, caid));
        hmac.setSession(admin, userAdminSession, certSession);
		boolean res = hmac.verifyOrExtract(req, null);
		assertTrue("Verifying the message authenticity using HMAC failed.", res);
		assertNotNull("HMAC returned null password." + hmac.getAuthenticationString());
		assertEquals("HMAC returned the wrong password", "foo123", hmac.getAuthenticationString());
	}
	
	public void test02EEModule() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, InvalidAlgorithmParameterException,
	EjbcaException, javax.ejb.ObjectNotFoundException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {

		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed." + msg);

		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);

		EndEntityCertificateAuthenticationModule eemodule = new EndEntityCertificateAuthenticationModule(caAdminSession.getCAInfo(admin, caid).getName());
		eemodule.setSession(admin, caAdminSession, certSession, authorizationSession, eeProfileSession, userAdminSession);
		boolean res = eemodule.verifyOrExtract(msg, null);
		assertTrue("Verifying the message authenticity using EndEntityCertificate failed.", res);
		assertNotNull("EndEntityCertificate authentication module returned null password." + eemodule.getAuthenticationString());
		//Should be a random generated password
		assertNotSame("EndEntityCertificate authentication module returned the wrong password", "foo123", eemodule.getAuthenticationString());
	}
	
	public void test03HMACCrmfReq() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert1 = checkCmpCertRepMessage(userDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
	}
	
	public void test04HMACRevReq() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));		
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		Collection<Certificate> certs = certSession.findCertificatesBySubjectAndIssuer(admin, userDN, issuerDN);
		log.debug("Found " + certs.size() + " certificates for userDN \"" + userDN + "\"");
		Certificate cert = null, tmp=null;
		Iterator<Certificate> itr = certs.iterator();
		while(itr.hasNext()) {
			tmp = itr.next();
			if(!certSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
				cert = tmp;
				break;
			}
		}
		if(cert == null) {
			createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123");
			KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
			cert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		}
		assertNotNull("No certificate to revoke.", cert);
		
		
		PKIMessage msg = genRevReq(issuerDN, userDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false);
		assertNotNull("Generating RevocationRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), true, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
	}
	
	public void test05EECrmfReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed." + msg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);
        msg.getHeader().setSenderKID(new DEROctetString(nonce));

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);
		
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
	}
	
	public void test06EERevReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

		Collection<Certificate> certs = certSession.findCertificatesBySubjectAndIssuer(admin, userDN, issuerDN);
		log.debug("Found " + certs.size() + " certificates for userDN \"" + userDN + "\"");
		Certificate cert = null, tmp=null;
		Iterator<Certificate> itr = certs.iterator();
		while(itr.hasNext()) {
			tmp = itr.next();
			if(!certSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
				cert = tmp;
				break;
			}
		}
		if(cert == null) {
			createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123");
			KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
			cert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		}
		assertNotNull("No certificate to revoke.", cert);
		
		PKIMessage msg = genRevReq(issuerDN, userDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false);	
		assertNotNull("Generating CrmfRequest failed." + msg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);		 

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);
		
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), true, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
	}
	
	public void test07EERevReqWithUnknownCA() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);	
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
	 		
		Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(admin, userDN, issuerDN);
		log.debug("Found " + certs.size() + " certificates for userDN \"" + userDN + "\"");
		Certificate cert = null, tmp=null;
		Iterator<Certificate> itr = certs.iterator();
		while(itr.hasNext()) {
			tmp = itr.next();
			if(!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
				cert = tmp;
				break;
			}
		}
		if(cert == null) {
			createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123");
			KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
			cert = signSession.createCertificate(admin, "cmprevuser1", "foo123", admkeys.getPublic());
		}
		assertNotNull("No certificate to revoke.", cert);
		
		
		PKIMessage msg = genRevReq("CN=cmprevuser1,C=SE", userDN, CertTools.getSerialNumber(cert), cert, nonce, transid, false);  
		assertNotNull("Generating CrmfRequest failed.", msg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);     
		
		String adminName = "cmpTestAdmin";
		createUser(adminName, "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, adminName, "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, adminName, adminName + "@primekey.se");
		setupAccessRights(adm);
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);
		
		final ByteArrayOutputStream bao = new ByteArrayOutputStream();
		final DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(msg);
		final byte[] ba = bao.toByteArray();
		// Send request and receive response
		final byte[] resp = sendCmpHttp(ba, 200);       
		checkCmpResponseGeneral(resp, "C=SE,CN=cmprevuser1", userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
		//int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
		//assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
		assertNotNull(respObject);
		
		PKIBody body = respObject.getBody();
		assertEquals(23, body.getTagNo());
		String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
		String expectedErrMsg = "CA with DN 'C=SE,CN=cmprevuser1' is unknown";
		assertEquals(expectedErrMsg, errMsg);
	}

	public void test08EECrmfReqMultipleAuthModules() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		String modules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
		String parameters = "foo123" + ";" + "AdminCA1";
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed." + msg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);		 

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);
		
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
        
        VerifyPKIMessage verifier = new VerifyPKIMessage(caAdminSession.getCAInfo(admin, caid), admin, caAdminSession, userAdminSession, certSession, authorizationSession, eeProfileSession);
        boolean verify = verifier.verify(msg, null);
        assertTrue("Verifying PKIMessage failed", verify);
        assertEquals(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, verifier.getUsedAuthenticationModule().getName());
	}

	public void test09HMACCrmfReqMultipleAuthenticationModules() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
        final String pbeSecret = "foo123hmac";
		String modules = CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ";" + CmpConfiguration.AUTHMODULE_HMAC;
        String parameters = "-;AdminCA1;"+pbeSecret;
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        confSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        assertTrue("The response protection was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe"));

		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, pbeSecret, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, pbeSecret);
        Certificate cert1 = checkCmpCertRepMessage(userDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
        
        VerifyPKIMessage verifier = new VerifyPKIMessage(caAdminSession.getCAInfo(admin, caid), admin, caAdminSession, userAdminSession, certSession, authorizationSession, eeProfileSession);
        boolean verify = verifier.verify(req, null);
        assertTrue("Verifying PKIMessage failed", verify);
        assertEquals(CmpConfiguration.AUTHMODULE_HMAC, verifier.getUsedAuthenticationModule().getName());
	}

	public void test10HMACCrmfReqWrongAuthenticationModule() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());

		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID"));		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());


		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123hmac", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);   
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        String expectedErrMsg = "Unrecognized authentication module '" + CmpConfiguration.AUTHMODULE_DN_PART_PWD + "'";
        assertEquals(expectedErrMsg, errMsg);
	}
	

	public void test11EECrmfCheckAdminAuthorization() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception  {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1"));
		confSession.updateProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "true");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "true"));
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed." + msg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);		 
        msg.getHeader().setSenderKID(new DEROctetString(nonce));
		
		String adminName ="cmpTestUnauthorizedAdmin"; 
		createUser(adminName , "CN=" + adminName + ",C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, adminName, "foo123", admkeys.getPublic());
		addExtraCert(msg, admCert);
		signPKIMessage(msg, admkeys);
		assertNotNull(msg);
		
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("\"CN=cmpTestUnauthorizedAdmin,C=SE\" is not an authorized administrator.", errMsg);
        
		confSession.updateProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false"));
		
        final byte[] resp2 = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp2, issuerDN, userDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert2 = checkCmpCertRepMessage(userDN, cacert, resp2, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);
	}
	
	public void test12CrmfReqClientModeHMAC() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client"));		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
        confSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        assertTrue("The response protection was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature"));

		String clientUsername = "clientTestUser";
		String clientDN = "CN=" + clientUsername + ",C=SE";
		String clientPassword = "foo123client";
		try{
			userAdminSession.revokeAndDeleteUser(admin, clientUsername, ReasonFlags.unused);
		} catch(Exception e) {}
		createUser(clientUsername, clientDN, clientPassword);
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        // 
        // Try a request with no issuerDN in the certTemplate
		createUser(clientUsername, clientDN, clientPassword);
		PKIMessage msgNoIssuer = genCertReq(null, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msgNoIssuer);
        PKIMessage reqNoIssuer = protectPKIMessage(msgNoIssuer, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        final ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
        final DEROutputStream out2 = new DEROutputStream(bao2);
        out2.writeObject(reqNoIssuer);
        final byte[] ba2 = bao2.toByteArray();
        // Send request and receive response
        final byte[] respNoIssuer = sendCmpHttp(ba2, 200);        
        checkCmpResponseGeneral(respNoIssuer, issuerDN, clientDN, cacert, reqNoIssuer.getHeader().getSenderNonce().getOctets(), reqNoIssuer.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert2 = checkCmpCertRepMessage(clientDN, cacert, respNoIssuer, reqNoIssuer.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert2);
        
        // Send a confirm message to the CA
        String hash = CertTools.getFingerprintAsString(cert2);
        int reqId = reqNoIssuer.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        final ByteArrayOutputStream bao3 = new ByteArrayOutputStream();
        final DEROutputStream out3 = new DEROutputStream(bao3);
        out3.writeObject(confirm);
        final byte[] ba3 = bao3.toByteArray();
        // Send request and receive response
        byte[] resp3 = sendCmpHttp(ba3, 200);
        checkCmpResponseGeneral(resp3, issuerDN, userDN, cacert, nonce, transid, true, null);
        checkCmpPKIConfirmMessage(userDN, cacert, resp3);

	}
	
	public void test13HMACModuleInClientMode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, 
						InvalidAlgorithmParameterException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, 
						EjbcaException, java.lang.Exception {
		
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		
		String clientUsername = "clientTestUser";
		String clientDN = "CN=" + clientUsername + ",C=SE";
		String clientPassword = "foo123client";
		try {
			userAdminSession.revokeAndDeleteUser(admin, clientUsername, ReasonFlags.unused);
		} catch(Exception e) {}
		createUser(clientUsername, clientDN, clientPassword);
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caAdminSession.getCAInfo(admin, caid));
        hmac.setSession(admin, userAdminSession, certSession);
		boolean res = hmac.verifyOrExtract(req, null);
		assertTrue("Verifying the message authenticity using HMAC failed.", res);
		assertNotNull("HMAC returned null password." + hmac.getAuthenticationString());
		assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());
		
		// Test the same but without issuerDN in the request
		msg = genCertReq(null, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);	
		assertNotNull("Generating CrmfRequest failed.", msg);
        req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);
		res = hmac.verifyOrExtract(req, null);
		assertTrue("Verifying the message authenticity using HMAC failed.", res);
		assertNotNull("HMAC returned null password." + hmac.getAuthenticationString());
		assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());
	}
	
	public void test14CrmfReqClientModeRegToken() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		String clientUsername = "clientTestUser";
		String clientDN = "CN=" + clientUsername + ",C=SE";
		String clientPassword = "foo123client";
		try{
			userAdminSession.revokeAndDeleteUser(admin, clientUsername, ReasonFlags.unused);
		} catch(Exception e) {}
		createUser(clientUsername, clientDN, "foo123");
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
	}
	
	public void test15CrmfReqClientModeMultipleModules() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		String authmodules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123;-");

		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		String clientUsername = "clientTestUser";
		String clientDN = "CN=" + clientUsername + ",C=SE";
		try{
			userAdminSession.revokeAndDeleteUser(admin, clientUsername, ReasonFlags.unused);
		} catch(Exception e) {}
		createUser(clientUsername, clientDN, "foo123");
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
//        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
//        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), true, null);
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
        
        VerifyPKIMessage verifier = new VerifyPKIMessage(caAdminSession.getCAInfo(admin, caid), admin, caAdminSession, userAdminSession, certSession, authorizationSession, eeProfileSession);
        boolean verify = verifier.verify(msg, null);
        assertTrue(verify);
        assertEquals(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, verifier.getUsedAuthenticationModule().getName());
	}
	
	public void test16HMACCrmfReqClientModeHMACInvalidPassword() throws Exception {
		assertFalse("Configurations have not been backed up before starting testing.", confSession.backupConfiguration());
		
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
		confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client"));		
		confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
		ConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
		assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
		
		String clientUsername = "clientTestUser";
		String clientDN = "CN=" + clientUsername + ",C=SE";
		String clientPassword = "foo123client";
		try{
			userAdminSession.revokeAndDeleteUser(admin, clientUsername, ReasonFlags.unused);
		} catch(Exception e) {}
		createUser(clientUsername, clientDN, "foo123ee");
		
		KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		
		PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null);
		assertNotNull("Generating CrmfRequest failed." + msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID().getOctets(), false, null);
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        String expectedErrMsg = "Authentication failed for message. clientTestUser.";
        assertEquals(expectedErrMsg, errMsg);
	}
	
    /** Test CMP initial request against EJBCA CMP in client mode (operationmode=normal) using End Entity certificate signature authentication, 
     * i.e. the request is signed by a certificate of the same end entity making the request, and this signature is used for authenticating the end entity.
     * Test:
     * - Request signed by a fake certificate, i.e. one that is not in the database (FAIL)
     * - Request signed by a certificate that beloongs to another user (FAIL)
     * - Request signed by a proper certificate but where user status is not NEW (FAIL)
     * - Request signed by a proper, but revoked certificate (FAIL)
     * - A working request signed by a proper, unrevoked certificate and user status is NEW (SUCCESS)
     * 
     * @throws Exception on some errors
     */
    public void test17CrmfReqClientModeEESignature() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));        
        confSession.updateProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_CHECKADMINAUTHORIZATION, "false"));        
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.", confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        
        final String testUserDN = "CN=cmptestuser16,C=SE";
        final String testUsername = "cmptestuser16";
        final String otherUserDN = "CN=cmptestotheruser16,C=SE";
        final String otherUsername = "cmptestotheruser16";
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            KeyPair fakeKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            createUser(testUsername, testUserDN, "foo123");
            // A real certificate that can be used to sign the message
            Certificate cert = signSession.createCertificate(admin, testUsername, "foo123", keys.getPublic());
            // A fake certificate that should not be valid
            Certificate fakeCert = CertTools.genSelfCert(testUserDN, 30, null, fakeKeys.getPrivate(), fakeKeys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);

            // Step 1 sign with fake certificate, should not be valid as end entity authentication
            {
                PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null); 
                assertNotNull("Generating CrmfRequest failed.", msg);            
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                msg.getHeader().setProtectionAlg(pAlg);      
                addExtraCert(msg, fakeCert);
                signPKIMessage(msg, fakeKeys);
                assertNotNull(msg);
                //******************************************''''''
                final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
                sig.initVerify(fakeCert.getPublicKey());
                sig.update(msg.getProtectedBytes());
                boolean verified = sig.verify(msg.getProtection().getBytes());
                assertTrue("Signing the message failed.", verified);
                //***************************************************

                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200);        
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
                PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
                assertNotNull(respObject);
                PKIBody body = respObject.getBody();
                assertEquals(23, body.getTagNo());
                String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
                String expectedErrMsg = "The End Entity certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
                assertEquals(expectedErrMsg, errMsg);
            }
            // Step 2, sign the request with a certificate that does not belong to the user
            {
                KeyPair otherKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                createUser(otherUsername, otherUserDN, "foo123");
                // A real certificate that can be used to sign the message
                Certificate othercert = signSession.createCertificate(admin, otherUsername, "foo123", otherKeys.getPublic());
                PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null); 
                assertNotNull("Generating CrmfRequest failed.", msg);            
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                msg.getHeader().setProtectionAlg(pAlg);      
                addExtraCert(msg, othercert);
                signPKIMessage(msg, otherKeys);
                assertNotNull(msg);
                //******************************************''''''
                final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
                sig.initVerify(othercert.getPublicKey());
                sig.update(msg.getProtectedBytes());
                boolean verified = sig.verify(msg.getProtection().getBytes());
                assertTrue("Signing the message failed.", verified);
                //***************************************************

                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200);        
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
                PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
                assertNotNull(respObject);
                PKIBody body = respObject.getBody();
                assertEquals(23, body.getTagNo());
                String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
                String expectedErrMsg = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+testUsername+"'.";
                assertEquals(expectedErrMsg, errMsg);
            }
            // Step 3 sign with the real certificate, but user status is not NEW
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null); 
            assertNotNull("Generating CrmfRequest failed.", msg);            
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            msg.getHeader().setProtectionAlg(pAlg);      
            addExtraCert(msg, cert);
            signPKIMessage(msg, keys);
            assertNotNull(msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
            sig.initVerify(cert.getPublicKey());
            sig.update(msg.getProtectedBytes());
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);        
            // This should have failed
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
            PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);
            PKIBody body = respObject.getBody();
            assertEquals(23, body.getTagNo());
            String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
            String expectedErrMsg = "Got request with status GENERATED (40), NEW, FAILED or INPROCESS required: cmptestuser16.";
            assertEquals(expectedErrMsg, errMsg);
                
            // Step 4 now set status to NEW, and a clear text password, then it should finally work
            createUser(testUsername, testUserDN, "randompasswordhere");
            // Send request and receive response
            final byte[] resp2 = sendCmpHttp(ba, 200);                    
            Certificate cert2 = checkCmpCertRepMessage(testUserDN, cacert, resp2, msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert2);
            // Step 5, revoke the certificate and try again
            {
                certSession.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, null);
                final byte[] resp3 = sendCmpHttp(ba, 200);        
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID().getOctets(), false, null);
                PKIMessage respObject3 = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp3)).readObject());
                assertNotNull(respObject);
                PKIBody body3 = respObject3.getBody();
                assertEquals(23, body3.getTagNo());
                String errMsg3 = body3.getError().getPKIStatus().getStatusString().getString(0).getString();
                String expectedErrMsg3 = "The End Entity certificate attached to the PKIMessage in the extraCert field is revoked.";
                assertEquals(expectedErrMsg3, errMsg3);
            }
        } finally {
            userAdminSession.revokeAndDeleteUser(admin, testUsername, ReasonFlags.unused);
            userAdminSession.revokeAndDeleteUser(admin, otherUsername, ReasonFlags.unused);
        }
    }
	
	public void test99RestoreConf() {
		assertTrue("Restoring configuration faild.", confSession.restoreConfiguration());
		try {
			userAdminSession.revokeAndDeleteUser(admin, username, ReasonFlags.unused);
			userAdminSession.revokeAndDeleteUser(admin, "cmpTestUnauthorizedAdmin", ReasonFlags.keyCompromise);
		} catch(Exception e){}
		
	}	
	
	private void setCAID() {
		// Try to use AdminCA1 if it exists
		final CAInfo adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");

		if (adminca1 == null) {
			final Collection<Integer> caids;

			caids = caSession.getAvailableCAs(admin);
			final Iterator<Integer> iter = caids.iterator();
			int tmp = 0;
			while (iter.hasNext()) {
				tmp = iter.next().intValue();
				if(tmp != 0)	break;
			}
			caid = tmp;
		} else {
			caid = adminca1.getCAId();
		}
		if (caid == 0) {
			assertTrue("No active CA! Must have at least one active CA to run tests!", false);
		}
	}
	
	private void setCaCert() {
		final CAInfo cainfo;

		cainfo = caAdminSession.getCAInfo(admin, caid);

		Collection<Certificate> certs = cainfo.getCertificateChain();
		if (certs.size() > 0) {
			Iterator<Certificate> certiter = certs.iterator();
			Certificate cert = certiter.next();
			String subject = CertTools.getSubjectDN(cert);
			if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
				// Make sure we have a BC certificate
				try {
					cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
				} catch (Exception e) {
					throw new Error(e);
				}
			} else {
				cacert = null;
			}
		} else {
			log.error("NO CACERT for caid " + caid);
			cacert = null;
		}
	}
	
	private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
		ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
		ASN1InputStream         dIn = new ASN1InputStream(bIn);
		ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
		X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
		msg.addExtraCert(extraCert);
	}
	
	private void signPKIMessage(PKIMessage msg, KeyPair keys) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
		sig.initSign(keys.getPrivate());
		sig.update(msg.getProtectedBytes());
		byte[] eeSignature = sig.sign();			
		msg.setProtection(new DERBitString(eeSignature));	
	}

    private UserDataVO createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, 
    			WaitingForApprovalException, EjbcaException, Exception {

    	UserDataVO user = new UserDataVO(username, subjectDN, caid, null, username+"@primekey.se", SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
        SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
    	user.setPassword(password);
    	try {
    		userAdminSession.addUser(admin, user, true);
    		// usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
    		log.debug("created user: " + username);
    	} catch (Exception e) {
    		log.debug("User " + username + " already exists. Setting the user status to NEW");
    		userAdminSession.changeUser(admin, user, true);
    		userAdminSession.setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}

    	return user;

    }
    
    private void setupAccessRights(Admin adm) throws Exception {
        
    	boolean adminExists = false;
    	AdminGroup admingroup = adminGroupSession.getAdminGroup(adm, AdminGroup.TEMPSUPERADMINGROUP);
    	Iterator<AdminEntity> iter = admingroup.getAdminEntities().iterator();
    	while (iter.hasNext()) {
    		AdminEntity adminEntity = iter.next();
    		if (adminEntity.getMatchValue().equals(adm.getUsername())) {
    			adminExists = true;
            }
    	}

    	if (!adminExists) {
    		List<AdminEntity> list = new ArrayList<AdminEntity>();
    		list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASE, adm.getUsername(), caid));
    		adminEntitySession.addAdminEntities(adm, AdminGroup.TEMPSUPERADMINGROUP, list);
    		authorizationSession.forceRuleUpdate(adm);
    	}
    	
    	BatchMakeP12 batch = new BatchMakeP12();
    	batch.setMainStoreDir("p12");
    	batch.createAllNew();
    }

}
