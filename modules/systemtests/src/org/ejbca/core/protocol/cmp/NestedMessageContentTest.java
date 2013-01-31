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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.core.ejb.authorization.AdminEntitySessionRemote;
import org.cesecore.core.ejb.authorization.AdminGroupSessionRemote;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.ConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;
import org.hibernate.ObjectNotFoundException;
import org.junit.rules.TemporaryFolder;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * This will the the different kind of CMP messages that can be sent as NestedMessageContent and if 
 * they are verified correctly
 * 
 * @version $Id: NestedMessageContentTest.java 13120 2011-11-07 08:38:36Z aveen4711 $
 *
 */
public class NestedMessageContentTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(NestedMessageContentTest.class);
	
    private Admin admin;
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private CertificateProfileSession certProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    private ConfigurationSessionRemote confSession = InterfaceCache.getConfigurationSession();
    private AuthorizationSession authorizationSession = InterfaceCache.getAuthorizationSession();
    private AdminGroupSessionRemote adminGroupSession = InterfaceCache.getAdminGroupSession();
    private AdminEntitySessionRemote adminEntitySession = InterfaceCache.getAdminEntitySession();
    private CertificateStoreSession certSession = InterfaceCache.getCertificateStoreSession();
    
    private int caid;
    private Certificate cacert;
    private String subjectDN;
    private String issuerDN;
    private String raCertsPath = "/tmp/racerts";
	private TemporaryFolder folder = new TemporaryFolder();
	
	public NestedMessageContentTest(String arg0) throws IOException {
		super(arg0);
        
        CryptoProviderTools.installBCProvider();

		// Create a temporary directory to store ra certificates, use JUnits TemporaryFolder that is deleted on exit
		File createdFolder = folder.newFolder("racerts");
		raCertsPath = createdFolder.getCanonicalPath();
		
		subjectDN = "CN=nestedCMPTest,C=SE";
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
        // Configure CMP for this test, we allow custom certificate serial numbers
    	CertificateProfile profile = new EndUserCertificateProfile();
    	profile.setAllowValidityOverride(true);
    	profile.saveData();
    	try {
    		certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
		} catch (CertificateProfileExistsException e) {
			log.error("Could not create certificate profile.", e);
		}
        int cpId = certProfileSession.getCertificateProfileId(admin, "CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false);	// Don't use field from "email" data
        try {
        	eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
		} catch (EndEntityProfileExistsException e) {
			log.error("Could not create end entity profile.", e);
		}
        // Configure CMP for this test
		confSession.backupConfiguration();
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "AdminCA1");
        // Also update raCerts path locally to be able to verify locally
        ConfigurationHolder.instance().setProperty(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath);
        
        //Set the caid and cacert
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;

        adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");

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
        
        issuerDN = cacert != null ? ((X509Certificate) cacert).getIssuerDN().getName() : "CN=AdminCA1,O=EJBCA Sample,C=SE";
		
	}

	public void test01CrmfReq() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
        int reqID = crmfMsg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
    	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(seq, 20); // NestedMessageContent
        assertNotNull("Failed to create nested message PKIBody", myPKIBody);

        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
        assertNotNull("Failed to create nested message PKIMessage", myPKIMessage);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raCrmfSigner", "foo123", raKeys, null, null);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.getDERObject().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert = checkCmpCertRepMessage(subjectDN, cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
   	}
	
	public void test02Verify() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
        	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raSignerVerify", "foo123", raKeys, null, null);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);
        	
        NestedMessageContent nestedMsg = new NestedMessageContent(myPKIMessage);
        boolean verify = nestedMsg.verify();
        assertTrue("NestedMessageVerification failed.", verify);
		
	}
	
	public void test03RevReq() throws NoSuchAlgorithmException, AuthorizationDeniedException, EjbcaException, CertificateEncodingException, IOException, Exception{
		Collection<Certificate> certs = certSession.findCertificatesBySubjectAndIssuer(admin, subjectDN, issuerDN);
		log.debug("Found " + certs.size() + " certificates for userDN \"" + subjectDN + "\"");
		Certificate cert = null, tmp=null;
		Iterator<Certificate> itr = certs.iterator();
		while(itr.hasNext()) {
			tmp = itr.next();
			if(!certSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
				cert = tmp;
				break;
			}
		}
		assertNotNull("Could not find a suitable certificate to revoke.", cert);
	
		//----------- creating the revocation signed request-------------------
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
		PKIMessage revMsg = genRevReq(issuerDN, subjectDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false);	
		assertNotNull("Generating CrmfRequest failed." + revMsg);
		
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		revMsg.getHeader().setProtectionAlg(pAlg);		 
		revMsg.getHeader().setSenderKID(new DEROctetString(nonce));

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(revMsg, admCert);
		signPKIMessage(revMsg, admkeys);
		assertNotNull(revMsg);
		
		
		//----------------- Creating the nested PKIMessage -----------------------
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] reqNonce = CmpMessageHelper.createSenderNonce();
        final byte[] reqTransid = CmpMessageHelper.createSenderNonce();
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(reqNonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(reqTransid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( revMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(seq, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raRevSigner", "foo123", raKeys, null, null);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);        
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, nonce, transid, false, null);
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
	}

	public void test04CrmfRACertExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
        int reqID = crmfMsg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
    	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody myPKIBody = new PKIBody(seq, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raSignerTest04", "foo123", raKeys, null, null);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.getDERObject().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
        Certificate cert = checkCmpCertRepMessage(subjectDN, cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
        
        NestedMessageContent nestedContent = new NestedMessageContent(myPKIMessage);
        boolean ret = nestedContent.verify();
        assertTrue("The message verification failed, yet the a certificate was returned.", ret);
        
   	}

	public void test05CrmfRACertDoesNotExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
    	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // nonce
        DEROctetString dernonce = new DEROctetString(nonce);
        myPKIHeader.setSenderNonce(dernonce);
        myPKIHeader.setRecipNonce(dernonce);
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		// Don't create a certificate, so there is no RA cert authorized on the server side.
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA", errMsg);
        
        NestedMessageContent nestedContent = new NestedMessageContent(myPKIMessage);
        boolean ret = nestedContent.verify();
        assertFalse("The message verification failed, yet the a certificate was returned.", ret);
        
   	}
	
	public void test06NotNestedMessage() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		OptionalValidity myOptionalValidity = new OptionalValidity();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		myOptionalValidity.setNotBefore(nb);
		myOptionalValidity.setNotAfter(na);

		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		CertTemplate myCertTemplate = new CertTemplate();
		myCertTemplate.setValidity( myOptionalValidity );
		myCertTemplate.setIssuer(new X509Name(issuerDN));
		myCertTemplate.setSubject(new X509Name(subjectDN));
		byte[]                  bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
		myCertTemplate.setPublicKey(keyInfo);
		// If we did not pass any extensions as parameter, we will create some of our own, standard ones
		
        X509Extensions exts = null;
        if (exts == null) {
        	// SubjectAltName
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            DEROutputStream         dOut = new DEROutputStream(bOut);
            Vector<X509Extension> values = new Vector<X509Extension>();
            Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
            // KeyUsage
            int bcku = 0;
            bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
            X509KeyUsage ku = new X509KeyUsage(bcku);
            bOut = new ByteArrayOutputStream();
            dOut = new DEROutputStream(bOut);
            dOut.writeObject(ku);
            byte[] value = bOut.toByteArray();
            X509Extension kuext = new X509Extension(false, new DEROctetString(value));
            values.add(kuext);
            oids.add(X509Extensions.KeyUsage);

            // Make the complete extension package
            exts = new X509Extensions(oids, values);
        }
        myCertTemplate.setExtensions(exts);
        CertRequest myCertRequest = new CertRequest(new DERInteger(4), myCertTemplate);
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest);
        ProofOfPossession myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
        myCertReqMsg.setPop(myProofOfPossession);
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123"));
        myCertReqMsg.addRegInfo(av);

        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(subjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN().getName())));
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        PKIBody myPKIBody = new PKIBody(myCertReqMessages, 20); // nestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raSignerTest06", "foo123", raKeys, null, null);
		signPKIMessage(myPKIMessage, raKeys);
        
        assertNotNull("Failed to create PKIHeader", myPKIHeader);
        assertNotNull("Failed to create PKIBody", myPKIBody);
        assertNotNull("Failed to create PKIMessage", myPKIMessage);
		
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("Wrong error message", "unknown object in getInstance: org.bouncycastle.asn1.DERSequence", errMsg);
   	}
	
	public void test07ExpiredRACert() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		log.info(">test07ExpiredRACert()");
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
    	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));
        myPKIHeader.setRecipNonce(new DEROctetString(nonce));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		
		long nbTime = (new Date()).getTime() - 1000000L;
    	org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new Date(nbTime));
    	org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
		createRACertificate("raExpiredSignerTest07", "foo123", raKeys, nb.getDate(), na.getDate());
		Thread.sleep(5000);
		signPKIMessage(myPKIMessage, raKeys);
        
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.getDERObject().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, myPKIMessage.getHeader().getSenderNonce().getOctets(), myPKIMessage.getHeader().getTransactionID().getOctets(), false, null);
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA", errMsg);
		log.info("<test07ExpiredRACert()");
   	}
	
	public void test08MissingSignature() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		log.info(">test07ExpiredRACert()");
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createEESignedCrmfReq(subjectDN);
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
    	
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));
        myPKIHeader.setRecipNonce(new DEROctetString(nonce));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.getDERObject().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, myPKIMessage.getHeader().getSenderNonce().getOctets(), myPKIMessage.getHeader().getTransactionID().getOctets(), false, null);
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getTagNo());
        String errMsg = body.getError().getPKIStatus().getStatusString().getString(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA", errMsg);
		log.info("<test07ExpiredRACert()");
   	}
	
	
    public void testZZZCleanUp() throws Exception {
    	log.trace(">testZZZCleanUp");
    	
		try {
			userAdminSession.revokeAndDeleteUser(admin, "cmpTestAdmin", ReasonFlags.keyCompromise);
		} catch(Exception e){
			// NOPMD
		}
		try {
			userAdminSession.revokeAndDeleteUser(admin, "nestedCMPTest", ReasonFlags.keyCompromise);
		} catch(Exception e){
			// NOPMD
		}
		
    	certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");        
		eeProfileSession.removeEndEntityProfile(admin, "CMPTESTPROFILE");
		
		assertTrue("Could not restore CMP configurations", confSession.restoreConfiguration());
        
        File createdFolder = new File(raCertsPath);
        File[] certs = createdFolder.listFiles();
        for(int i=0; i<certs.length; i++) {
            certs[i].delete();
        }
        createdFolder.delete();
		
    	log.trace("<testZZZCleanUp");
    }
	
	private PKIMessage createEESignedCrmfReq(String userSubjectDN) throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		//createUser("cmptest", "C=SE,O=PrimeKey,CN=cmptest", "foo123");
		
		byte[] senderNonce = CmpMessageHelper.createSenderNonce();
		byte[] transactionID = CmpMessageHelper.createSenderNonce();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		assertNotNull(nb);
		assertNotNull(na);
		
		KeyPair keys = null;
		keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage req = genCertReq(issuerDN, userSubjectDN, keys, cacert, senderNonce, transactionID, false, null, nb.getDate(), na.getDate(), null);
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		req.getHeader().setProtectionAlg(pAlg);
		req.getHeader().setSenderKID(new DEROctetString(senderNonce));

		createUser("cmpTestAdmin", "CN=cmpTestAdmin,C=SE", "foo123");
		KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
		Certificate admCert = signSession.createCertificate(admin, "cmpTestAdmin", "foo123", admkeys.getPublic());
		Admin adm = new Admin(admCert, "cmpTestAdmin", "cmpTestAdmin@primekey.se");
		setupAccessRights(adm);
		addExtraCert(req, admCert);
		signPKIMessage(req, admkeys);
		assertNotNull(req);
		
		return req;
	}
	
	private Certificate createRACertificate(String username, String password, KeyPair keys, Date notBefore, 
			Date notAfter) throws AuthorizationDeniedException, EjbcaException, CertificateException, FileNotFoundException,
			IOException, UserDoesntFullfillEndEntityProfile, ObjectNotFoundException, Exception {
		
		assertTrue("RACertPath is suppose to be \"" + raCertsPath + "\", instead it is \"" + confSession.getProperty(CmpConfiguration.CONFIG_RACERT_PATH, null) + "\".", confSession.verifyProperty(CmpConfiguration.CONFIG_RACERT_PATH, raCertsPath));
		
        createUser(username, "CN="+username, password);
        Certificate racert = signSession.createCertificate(admin, username, password, keys.getPublic(), X509KeyUsage.digitalSignature|X509KeyUsage.keyCertSign, notBefore, notAfter, certProfileSession.getCertificateProfileId(admin, "CMPTESTPROFILE"), caid);

        
        Vector<Certificate> certCollection = new Vector<Certificate>();
        certCollection.add(racert);
        byte[] pemRaCert = CertTools.getPEMFromCerts(certCollection);
        
        String raCertPath = confSession.getProperty(CmpConfiguration.CONFIG_RACERT_PATH, null);
        String filename = raCertPath + "/" + username + ".pem";
        File file = folder.newFile(filename);
        assertNotNull(file);
        FileOutputStream fout = new FileOutputStream(file);
        fout.write(pemRaCert);
        fout.flush();
        fout.close();        
        
        userAdminSession.deleteUser(admin, username);
        
        return racert;
	}
	
	private void signPKIMessage(PKIMessage msg, KeyPair keys) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
		sig.initSign(keys.getPrivate());
		sig.update(msg.getProtectedBytes());
		byte[] eeSignature = sig.sign();			
		msg.setProtection(new DERBitString(eeSignature));	
	}

    private UserDataVO createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
            EjbcaException, Exception {
    	
        UserDataVO user = new UserDataVO(username, subjectDN, caid, null, username+"@primekey.se", SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            userAdminSession.addUser(admin, user, false);
            // usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            userAdminSession.changeUser(admin, user, false);
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

	private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
		ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
		ASN1InputStream         dIn = new ASN1InputStream(bIn);
		ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
		X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
		msg.addExtraCert(extraCert);
	}
    

}
