package org.ejbca.core.protocol.ws.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Random;
import java.util.Vector;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.core.model.InternalResources;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;
import com.novosec.pkix.asn1.cmp.RevDetails;
import com.novosec.pkix.asn1.cmp.RevReqContent;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.PBMParameter;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

public class CMPNestedMessageTestBaseCommand {
	
    protected static final InternalResources intres = InternalResources.getInstance();

    private int lastNextInt = 0;
    final private static int howOftenToGenerateSameUsername = 3;	// 0 = never, 1 = 100% chance, 2=50% chance etc..
    
	protected Random random;
	protected X509Certificate cacert;
	protected KeyPair popokeys;
	protected String userDN;
    final protected byte[] nonce = new byte[16];
    final protected byte[] transid = new byte[16];
    final protected boolean isHttp;
    protected String hostname;
    protected int port;
    protected String urlPath;
    protected boolean firstTime;
    protected boolean isSign;
    final protected Provider bcProvider;
    protected CertificateFactory certificateFactory;

	
	public CMPNestedMessageTestBaseCommand() {
		
		this.random = new Random();
        this.userDN = "CN=CMPTestUserNr"+getRandomAndRepeated()+",serialNumber="+getFnrLra();
        random.nextBytes(this.nonce);
        random.nextBytes(this.transid);
        isHttp = true;
            
        this.firstTime = true;
        this.isSign = false;
        
        CryptoProviderTools.installBCProviderIfNotAvailable();

        this.bcProvider = new BouncyCastleProvider();
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509", this.bcProvider);
		} catch (CertificateException e) {
			e.printStackTrace(getPrintStream());
			System.exit(-1);
		}
	
	}
	
    
    protected CertRequest genCertReq(final String userDN, final X509Extensions extensions) throws IOException {
    	final OptionalValidity myOptionalValidity = new OptionalValidity();
    	final int day = 1000*60*60*24;
    	myOptionalValidity.setNotBefore( new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime()-day)) );
    	myOptionalValidity.setNotAfter( new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime()+10*day)) );

    	final CertTemplate myCertTemplate = new CertTemplate();
    	myCertTemplate.setValidity( myOptionalValidity );
    	myCertTemplate.setIssuer(new X509Name(this.cacert.getSubjectDN().getName()));
    	myCertTemplate.setSubject(new X509Name(userDN));
    	final byte[]                  bytes = popokeys.getPublic().getEncoded();
    	final ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
    	final ASN1InputStream         dIn = new ASN1InputStream(bIn);
    	final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
    	myCertTemplate.setPublicKey(keyInfo);
    	// If we did not pass any extensions as parameter, we will create some of our own, standard ones	
    	if (extensions == null) {
    		// SubjectAltName
    		// Some altNames
    		final Vector<X509Extension> values = new Vector<X509Extension>();
    		final Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
    		{
    			final GeneralNames san = CertTools.getGeneralNamesFromAltName("UPN=fooupn@bar.com,rfc822Name=rfc822Name@my.com");
    			final ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
    			final DEROutputStream         dOut = new DEROutputStream(bOut);
    			dOut.writeObject(san);
    			final byte value[] = bOut.toByteArray();
    			values.add(new X509Extension(false, new DEROctetString(value)));
    			oids.add(X509Extensions.SubjectAlternativeName);
    		}
    		{
    			// KeyUsage
    			final int bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
    			final X509KeyUsage ku = new X509KeyUsage(bcku);
    			final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    			final DEROutputStream dOut = new DEROutputStream(bOut);
    			dOut.writeObject(ku);
    			final byte value[] = bOut.toByteArray();
    			final X509Extension kuext = new X509Extension(false, new DEROctetString(value));
    			values.add(kuext);
    			oids.add(X509Extensions.KeyUsage);     
    		}
    		// Make the complete extension package
    		myCertTemplate.setExtensions(new X509Extensions(oids, values));
    	} else {
    		myCertTemplate.setExtensions(extensions);
    	}
    	
    	return new CertRequest(new DERInteger(4), myCertTemplate);
    }
    
    protected RevReqContent genRevReq(String issuerDN, BigInteger serNo, Certificate cacert,
            boolean crlEntryExtension) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
        CertTemplate myCertTemplate = new CertTemplate();
        myCertTemplate.setIssuer(new X509Name(issuerDN));
        myCertTemplate.setSerialNumber(new DERInteger(serNo));

        RevDetails myRevDetails = new RevDetails(myCertTemplate);
        ReasonFlags reasonbits = new ReasonFlags(ReasonFlags.keyCompromise);
        myRevDetails.setRevocationReason(reasonbits);
        if (crlEntryExtension) {
            CRLReason crlReason = new CRLReason(CRLReason.cessationOfOperation);
            X509Extension ext = new X509Extension(false, new DEROctetString(crlReason.getEncoded()));
            Hashtable<DERObjectIdentifier, X509Extension> ht = new Hashtable<DERObjectIdentifier, X509Extension>();
            ht.put(X509Extensions.ReasonCode, ext);
            myRevDetails.setCrlEntryDetails(new X509Extensions(ht));
        }

        RevReqContent myRevReqContent = new RevReqContent(myRevDetails);
        
        return myRevReqContent;
    }
    
    protected PKIMessage genPKIMessage(final boolean raVerifiedPopo,
           final CertRequest certRequest) throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {

    	final CertReqMsg myCertReqMsg = new CertReqMsg(certRequest);

    	ProofOfPossession myProofOfPossession;
    	if (raVerifiedPopo) {
    		// raVerified POPO (meaning there is no POPO)
    		myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
    	} else {
    		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    		final DEROutputStream mout = new DEROutputStream( baos );
    		mout.writeObject( certRequest );
    		mout.close();
    		final byte[] popoProtectionBytes = baos.toByteArray();
    		final Signature sig = Signature.getInstance( PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
    		sig.initSign(popokeys.getPrivate());
    		sig.update( popoProtectionBytes );

    		final DERBitString bs = new DERBitString(sig.sign());

    		final POPOSigningKey myPOPOSigningKey =	new POPOSigningKey(
    					new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption), bs);
    		//myPOPOSigningKey.setPoposkInput( myPOPOSigningKeyInput );
    		myProofOfPossession = new ProofOfPossession(myPOPOSigningKey, 1);           
    	}

    	myCertReqMsg.setPop(myProofOfPossession);

    	final AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123")); 
    	myCertReqMsg.addRegInfo(av);

    	final CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

    	final PKIHeader myPKIHeader = new PKIHeader( new DERInteger(2),
    								  new GeneralName(new X509Name(userDN)),
    								  new GeneralName(new X509Name(this.cacert.getSubjectDN().getName())) );
    	myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
    	myPKIHeader.setSenderNonce(new DEROctetString(nonce));
    	myPKIHeader.setTransactionID(new DEROctetString(transid));

    	final PKIBody myPKIBody = new PKIBody(myCertReqMessages, 0); // initialization request
    	return new PKIMessage(myPKIHeader, myPKIBody);   
    }

    protected PKIMessage signPKIMessage(final PKIMessage msg, PrivateKey signingKey) throws NoSuchAlgorithmException, NoSuchProviderException, 
    		InvalidKeyException, SignatureException {
    	PKIMessage message = msg;
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
		msg.getHeader().setProtectionAlg(pAlg);
    	final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "BC");
    	sig.initSign(signingKey);
    	sig.update(message.getProtectedBytes());
    	byte[] eeSignature = sig.sign();			
    	message.setProtection(new DERBitString(eeSignature));
    	return message;
    }
    
	protected void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
		ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
		ASN1InputStream         dIn = new ASN1InputStream(bIn);
		ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
		X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
		msg.addExtraCert(extraCert);
	}

    protected byte[] sendCmp(final byte[] message) throws Exception {
    	if (isHttp ) {
    		return sendCmpHttp(message);
    	}
    	return null;
    }

    private byte[] sendCmpHttp(final byte[] message) throws Exception {
    	    	
    	
    	final CMPSendHTTP send = CMPSendHTTP.doIt(message, hostname, port, urlPath, false);
    	if ( send.responseCode!=HttpURLConnection.HTTP_OK ) {
    		getPrintStream().println(intres.getLocalizedMessage("cmp.responsecodenotok", Integer.valueOf(send.responseCode)));
    		return null;
    	}
    	if ( send.contentType==null ) {
    		getPrintStream().println("No content type received.");
    		return null;
    	}
    	// Some appserver (Weblogic) responds with "application/pkixcmp; charset=UTF-8"
    	if ( !send.contentType.startsWith("application/pkixcmp") ) {
    		getPrintStream().println("wrong content type: "+send.contentType);
    	}
    	return send.response;
    }
    
    protected boolean checkCmpResponseGeneral(final byte[] retMsg, final boolean requireProtection) throws Exception {
    	//
    	// Parse response message
    	//
    	final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
    	if ( respObject==null ) {
    		getPrintStream().println("No command response message.");
    		return false;
    	}
    	
    	// The signer, i.e. the CA, check it's the right CA
    	final PKIHeader header = respObject.getHeader();
    	if ( header==null ) {
    		getPrintStream().println("No header in response message.");
    		return false;
    	}
    	// Check that the signer is the expected CA
    	final X509Name name = X509Name.getInstance(header.getSender().getName()); 
    	if ( header.getSender().getTagNo()!=4 || name==null || !name.equals(this.cacert.getSubjectDN()) ) {
    		getPrintStream().println("Not signed by right issuer.");
    	}

    	if ( header.getSenderNonce().getOctets().length!=16 ) {
    		getPrintStream().println("Wrong length of received sender nonce (made up by server). Is "+header.getSenderNonce().getOctets().length+" byte but should be 16.");
    	}

    	if ( !Arrays.equals(header.getRecipNonce().getOctets(), nonce) ) {
    		getPrintStream().println("recipient nonce not the same as we sent away as the sender nonce. Sent: "+Arrays.toString(nonce)+" Received: "+Arrays.toString(header.getRecipNonce().getOctets()));
    	}

    	if ( !Arrays.equals(header.getTransactionID().getOctets(), transid) ) {
    		getPrintStream().println("transid is not the same as the one we sent");
    	}
    	{
    		// Check that the message is signed with the correct digest alg
    		final AlgorithmIdentifier algId = header.getProtectionAlg();
    		if (algId==null || algId.getObjectId()==null || algId.getObjectId().getId()==null) {
    			if ( requireProtection ) {
    				getPrintStream().println("Not possible to get algorithm.");
    				return false;
    			}
    			return true;
    		}
    		final String id = algId.getObjectId().getId();
    		if ( id.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId()) ) {
    			if ( this.firstTime ) {
    				this.firstTime = false;
    				this.isSign = true;
    				getPrintStream().println("Signature protection used.");
    			} else if ( !this.isSign ) {
    				getPrintStream().println("Message password protected but should be signature protected.");
    			}
    		} else if ( id.equals(CMPObjectIdentifiers.passwordBasedMac.getId()) ) {
    			if ( this.firstTime ) {
    				this.firstTime = false;
    				this.isSign = false;
    				getPrintStream().println("Password (PBE) protection used.");
    			} else if ( this.isSign ) {
    				getPrintStream().println("Message signature protected but should be password protected.");
    			}
    		} else {
    			getPrintStream().println("No valid algorithm.");
    			getPrintStream().println(id);
    			getPrintStream().println(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
    			return false;
    		}
    	}
    	if ( this.isSign ) {
    		// Verify the signature
    		byte[] protBytes = respObject.getProtectedBytes();
    		final DERBitString bs = respObject.getProtection();
    		final Signature sig;
    		try {
    			sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
    			sig.initVerify(this.cacert);
    			sig.update(protBytes);
    			if ( !sig.verify(bs.getBytes()) ) {
    				getPrintStream().println("CA signature not verifying");
    			}
    		} catch ( Exception e) {
    			getPrintStream().println("Not possible to verify signature.");
    			e.printStackTrace(getPrintStream());
    		}           
    	} else {
    		//final DEROctetString os = header.getSenderKID();
    		//if ( os!=null )
    		//    StressTest.this.performanceTest.getLog().info("Found a sender keyId: "+new String(os.getOctets()));
    		// Verify the PasswordBased protection of the message
    		final PBMParameter pp; {
    			final AlgorithmIdentifier pAlg = header.getProtectionAlg();
    			// 	StressTest.this.performanceTest.getLog().info("Protection type is: "+pAlg.getObjectId().getId());
    			pp = PBMParameter.getInstance(pAlg.getParameters());
    		}
    		final int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
    		// StressTest.this.performanceTest.getLog().info("Iteration count is: "+iterationCount);
    		final AlgorithmIdentifier owfAlg = pp.getOwf();
    		// Normal OWF alg is 1.3.14.3.2.26 - SHA1
    		// StressTest.this.performanceTest.getLog().info("Owf type is: "+owfAlg.getObjectId().getId());
    		final AlgorithmIdentifier macAlg = pp.getMac();
    		// Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
    		// StressTest.this.performanceTest.getLog().info("Mac type is: "+macAlg.getObjectId().getId());
    		final byte[] salt = pp.getSalt().getOctets();
    		//log.info("Salt is: "+new String(salt));
    		final byte[] raSecret = new String("password").getBytes();
    		// HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7 
    		final String macOid = macAlg.getObjectId().getId();
    		final SecretKey key; {
    			byte[] basekey = new byte[raSecret.length + salt.length];
    			for (int i = 0; i < raSecret.length; i++) {
    				basekey[i] = raSecret[i];
    			}
    			for (int i = 0; i < salt.length; i++) {
    				basekey[raSecret.length+i] = salt[i];
    			}
    			// Construct the base key according to rfc4210, section 5.1.3.1
    			final MessageDigest dig = MessageDigest.getInstance(owfAlg.getObjectId().getId(), this.bcProvider);
    			for (int i = 0; i < iterationCount; i++) {
    				basekey = dig.digest(basekey);
    				dig.reset();
    			}
    			key = new SecretKeySpec(basekey, macOid);
    		}
    		final Mac mac = Mac.getInstance(macOid, this.bcProvider);
    		mac.init(key);
    		mac.reset();
    		final byte[] protectedBytes = respObject.getProtectedBytes();
    		final DERBitString protection = respObject.getProtection();
    		mac.update(protectedBytes, 0, protectedBytes.length);
    		byte[] out = mac.doFinal();
    		// 	My out should now be the same as the protection bits
    		byte[] pb = protection.getBytes();
    		if ( !Arrays.equals(out, pb) ) {
    			getPrintStream().println("Wrong PBE hash");
    		}
    	}
    	return true;
    }
    
    protected X509Certificate checkCmpCertRepMessage(final byte[] retMsg, final int requestId) throws IOException, CertificateException {
    	//
    	// Parse response message
    	//
    	final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
    	if ( respObject==null ) {
    		getPrintStream().println("No PKIMessage for certificate received.");
    		return null;
    	}
    	final PKIBody body = respObject.getBody();
    	if ( body==null ) {
    		getPrintStream().println("No PKIBody for certificate received.");
    		return null;
    	}
    	if ( body.getTagNo()!=1 ) {
    		getPrintStream().println("Cert body tag not 1.");
    		return null;
    	}
    	final CertRepMessage c = body.getIp();
    	if ( c==null ) {
    		getPrintStream().println("No CertRepMessage for certificate received.");
    		return null;
    	}
    	final CertResponse resp = c.getResponse(0);
    	if ( resp==null ) {
    		getPrintStream().println("No CertResponse for certificate received.");
    		return null;
    	}
    	if ( resp.getCertReqId().getValue().intValue()!=requestId ) {
    		getPrintStream().println("Received CertReqId is "+resp.getCertReqId().getValue().intValue()+" but should be "+requestId);
    		return null;
    	}
    	final PKIStatusInfo info = resp.getStatus();
    	if ( info==null ) {
    		getPrintStream().println("No PKIStatusInfo for certificate received.");
    		return null;
    	}
    	if ( info.getStatus().getValue().intValue()!=0 ) {
    		getPrintStream().println("Received Status is "+info.getStatus().getValue().intValue()+" but should be 0");
    		return null;
    	}
    	final CertifiedKeyPair kp = resp.getCertifiedKeyPair();
    	if ( kp==null ) {
    		getPrintStream().println("No CertifiedKeyPair for certificate received.");
    		return null;
    	}
    	final CertOrEncCert cc = kp.getCertOrEncCert();
    	if ( cc==null ) {
    		getPrintStream().println("No CertOrEncCert for certificate received.");
    		return null;
    	}
    	final X509CertificateStructure struct = cc.getCertificate();
    	if ( struct==null ) {
    		getPrintStream().println("No X509CertificateStructure for certificate received.");
    		return null;
    	}
    	final byte encoded[] = struct.getEncoded();
    	if ( encoded==null || encoded.length<=0 ) {
    		getPrintStream().println("No encoded certificate received.");
    		return null;
    	}
    	final X509Certificate cert = (X509Certificate)this.certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
    	if ( cert==null ) {
    		getPrintStream().println("Not possbile to create certificate.");
    		return null;
    	}
    	// Remove this test to be able to test unid-fnr
    	if ( cert.getSubjectDN().hashCode() != new X509Name(userDN).hashCode() ) {
    		getPrintStream().println("Subject is '"+cert.getSubjectDN()+"' but should be '"+userDN+'\'');
    		return null;
    	}
    	if ( cert.getIssuerX500Principal().hashCode() != this.cacert.getSubjectX500Principal().hashCode() ) {
    		getPrintStream().println("Issuer is '"+cert.getIssuerDN()+"' but should be '"+this.cacert.getSubjectDN()+'\'');
    		return null;
    	}
    	try {
    		cert.verify(this.cacert.getPublicKey());
    	} catch (Exception e) {
    		getPrintStream().println("Certificate not verifying. See exception");
    		e.printStackTrace(getPrintStream());
    		return null;
    	}
    	return cert;
    }
    
    protected PrintStream getPrintStream(){
        return System.out;
    }
    
    private String getRandomAllDigitString( int length ) {
    	final String s = Integer.toString( random.nextInt() );
    	return s.substring(s.length()-length);
    }
    public String getFnrLra() {
    	return getRandomAllDigitString(6)+getRandomAllDigitString(5)+'-'+getRandomAllDigitString(5);
    }
    private int getRandomAndRepeated() {
        // Initialize with some new value every time the test is started
        // Return the same value once in a while so we have multiple requests for the same username
        if ( this.lastNextInt==0 || howOftenToGenerateSameUsername==0 || random.nextInt()%howOftenToGenerateSameUsername!=0 ) {
            this.lastNextInt = random.nextInt();
        }
        return this.lastNextInt;
    }

    
    private static class CMPSendHTTP {
        /** Internal localization of logs and errors */

    	public String contentType;
    	public byte response[];
    	public int responseCode;
    	
    	private CMPSendHTTP(String ct, byte ba[], int rc) {
    		this.contentType = ct;
    		this.response = ba;
    		this.responseCode = rc;
    	}
    	public static CMPSendHTTP doIt(final byte[] message, final String hostName,
    	                               final int port, final String urlPath, final boolean doClose) throws Exception {
    		boolean isError = true;
    		final HttpURLConnection con = (HttpURLConnection)new URL("http://"+hostName+":"+port+(urlPath!=null ? urlPath:"/ejbca/publicweb/cmp")).openConnection();
    		try {
    			// POST the CMP request
    			// we are going to do a POST
    			con.setDoOutput(true);
    			con.setRequestMethod("POST");
    			con.setRequestProperty("Content-type", "application/pkixcmp");
    			con.connect();
    			// POST it
    			final OutputStream os = con.getOutputStream();
    			os.write(message);
    			os.close();

    			final String contentType = con.getContentType();
    			final int responseCode = con.getResponseCode();
    			if ( responseCode!=HttpURLConnection.HTTP_OK ) {
    				return new CMPSendHTTP( contentType, null, responseCode );
    			}
    			
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                // This works for small requests, and CMP requests are small enough
                InputStream in = con.getInputStream();
                int b = in.read();
                while (b != -1) {
                    baos.write(b);
                    b = in.read();
                }
                baos.flush();
                in.close();
                byte[] response = baos.toByteArray();

                if ( response==null || response.length<1 ) {
    				throw new Exception(intres.getLocalizedMessage("cmp.errornoasn1"));
    			}
    			isError = false;
    			return new CMPSendHTTP( contentType, response, responseCode );
    		} finally {
    			if ( doClose || isError ) {
    				con.disconnect();
    			}
    		}
    	}
    }

}
