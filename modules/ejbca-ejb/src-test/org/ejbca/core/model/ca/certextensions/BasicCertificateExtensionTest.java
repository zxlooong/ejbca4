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

package org.ejbca.core.model.ca.certextensions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * @version $Id: BasicCertificateExtensionTest.java 12665 2011-09-21 14:28:33Z netmackan $
 */
public class BasicCertificateExtensionTest extends TestCase {
	private static Logger log = Logger.getLogger(BasicCertificateExtensionTest.class);
        
        private static final InternalResources intres = InternalResources.getInstance();
	
	public void test01NullBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERNULL");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERNull);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());
	}

	public void test02IntegerBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERINTEGER");
		props.put("id1.property.value", "1234");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERInteger);
		assertTrue(((DERInteger)value).toString(),((DERInteger)value).toString().equals("1234"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("id1.property.encoding", "DERINTEGER");
		props.put("id1.property.value", "123SA4");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "123SA4", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);
	
	}
	
	public void test03BitStringBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBITSTRING");
		props.put("id1.property.value", "1111"); // this is 15 decimal
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);		
		byte[] result = {15};
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		assertEquals(((DERBitString)value).getBytes()[0],result[0]);
		assertEquals(((DERBitString)value).getPadBits(), 0);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
		
		props = new Properties();
		props.put("id1.property.encoding", "DERBITSTRING");
		// SSL Client and S/MIME in NetscapeCertType
		// This will be -96 in decimal, don't ask me why, but it is!
		props.put("id1.property.value", "10100000"); 
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERBitString);
		new BigInteger(((DERBitString)value).getBytes()); // Will throw if value is wrong
		//log.debug(bi.toString(2));
		//log.debug(bi.toString());
		//log.debug(((DERBitString)value).getBytes()[0]);
		assertEquals(((DERBitString)value).getBytes()[0],-96);
		assertEquals(((DERBitString)value).getPadBits(), 5);
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());	
	}	
	
	public void test04BooleanBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBOOLEAN");
		props.put("id1.property.value", "true");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERBoolean);
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("TRUE"));
		assertTrue(baseExt.getOID().equals("1.2.3"));
		assertTrue(baseExt.getId() == 1);
		assertFalse(baseExt.isCriticalFlag());			
		
        props.put("id1.property.value", "false");
		
		baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		value = getObject(baseExt.getValueEncoded(null, null, null, null, null));		
		assertTrue(((DERBoolean)value).toString(),((DERBoolean)value).toString().equals("FALSE"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERBOOLEAN");
		props.put("id1.property.value", "1sdf");
		boolean exceptionThrown = false;
		try{
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "1sdf", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);		
	}
	
	public void test05OctetBasicExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DEROCTETSTRING");
		props.put("id1.property.value", "DBE81232");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DEROctetString);
		assertTrue(((DEROctetString)value).toString(),((DEROctetString)value).toString().equalsIgnoreCase("#DBE81232"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DEROCTETSTRING");
		props.put("id1.property.value", "123SA4");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null));		  
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "123SA4", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);

	}	
	
	public void test06PritableStringExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "This is a printable string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERPrintableString);
		assertTrue(((DERPrintableString)value).toString(),((DERPrintableString)value).toString().equals("This is a printable string"));
		
		props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "This is a non  printable string ���");
		boolean exceptionThrown = false;
		try{	
		  baseExt = new BasicCertificateExtension();
		  baseExt.init(1, "1.2.3", false, props);
		  value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.illegalvalue", "This is a non  printable string ���", 1, "1.2.3"), e.getMessage());
		}
		assertTrue(exceptionThrown);
        
	}
	
	public void test07UTF8StringExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8STRING");
		props.put("id1.property.value", "This is a utf8 ��� ��string");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERUTF8String);
		assertTrue(((DERUTF8String)value).getString(),((DERUTF8String)value).getString().equals("This is a utf8 ��� ��string"));
        
	}
	
	public void test08WrongEncoding() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8sdfTRING");
		props.put("id1.property.value", "This is a utf8 ��� ��string");

		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		boolean exceptionThrown =false;
		try{	

			baseExt.getValueEncoded(null, null, null, null, null);
		}catch(CertificateExtentionConfigurationException e){
			exceptionThrown = true;
                        assertEquals(intres.getLocalizedMessage("certext.basic.incorrectenc", "DERUTF8sdfTRING", 1), e.getMessage());
		}
		assertTrue(exceptionThrown);
	}
	
	public void test09OidExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERBOJECTIDENTIFIER");
		props.put("id1.property.value", "1.1.1.255.1");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERObjectIdentifier);
		assertTrue(((DERObjectIdentifier)value).getId(),((DERObjectIdentifier)value).getId().equals("1.1.1.255.1"));        
	}

	public void test10SequencedExtension() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERUTF8STRING "); // Also test that we ignore spaces in the end here
		props.put("id1.property.nvalues", "3"); 
		props.put("id1.property.value1", "foo1");
		props.put("id1.property.value2", "foo2");
		props.put("id1.property.value3", "foo3");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
		DEREncodable value = getObject(baseExt.getValueEncoded(null, null, null, null, null));
		assertTrue(value.getClass().toString(),value instanceof DERSequence);
		DERSequence seq = (DERSequence)value;
		assertEquals(3, seq.size());
		Enumeration e = seq.getObjects();
		int i = 1;
		while(e.hasMoreElements()) {
			DEREncodable v = (DEREncodable)e.nextElement();
			assertTrue(v.getClass().toString(),v instanceof DERUTF8String);
			String str = ((DERUTF8String)v).getString();
			log.info(str);
			assertEquals(str,"foo"+i++);        
		}
	}
	
        
	/**
	 * Test with dynamic=true and no static value specified.
	 *
	 * There should be an exception if no value was specified in ExtendedInformation.
	 * But it should succeed if an value was specified in ExtendedInformation.
	 */
	public void test13DynamicTrueNoStatic() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Fail without value specified
		try {
			baseExt.getValueEncoded(userData, null, null, null, null);
			fail("Should have failed as no value was specified in EI.");
		} catch (CertificateExtentionConfigurationException ex) {
			assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
		}
		
		// Success with value specified
		userData.getExtendedinformation().setExtensionData("1.2.3", "The value 123");
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The value 123", ((DERPrintableString) value1).getString());
	}
	
	/**
	 * Test with dynamic=true and and a static value specified.
	 *
	 * The static value should be used if no value was specified in ExtendedInformation.
	 * The value from ExtendedInformation should be used if present.
	 */
	public void test14DynamicTrueStatic() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.dynamic", "true");
		props.put("id1.property.value", "The static value 123");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Without value in userdata, the static value is used
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value 123", ((DERPrintableString) value1).getString());
		
		// With value in userdata, that value is used
		userData.getExtendedinformation().setExtensionData("1.2.3", "A dynamic value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("A dynamic value 123", ((DERPrintableString) value1).getString());
	}
	
	/**
	 * Test with dynamic=true and and a static value specified where nvalues are used.
	 *
	 * The static values should be used if no value was specified in ExtendedInformation.
	 * The values from ExtendedInformation should be used if present.
	 */
	public void test15DynamicTrueStaticNvalues() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.dynamic", "true");
		props.put("id1.property.nvalues", "3");
		props.put("id1.property.value1", "The static value 1");
		props.put("id1.property.value2", "The static value 2");
		props.put("id1.property.value3", "The static value 3");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Without value in userdata, the static values is used
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value = in.readObject();
		assertTrue(value.getClass().toString(),value instanceof DERSequence);
		DERSequence seq = (DERSequence)value;
		assertEquals(3, seq.size());
		Enumeration e = seq.getObjects();
		int i = 1;
		while (e.hasMoreElements()) {
			DEREncodable v = (DEREncodable)e.nextElement();
			assertTrue(v.getClass().toString(), v instanceof DERPrintableString);
			String str = ((DERPrintableString) v).getString();
			assertEquals(str, "The static value " + i++);        
		}
		
		// With values in userdata, that values is used
		userData.getExtendedinformation().setExtensionData("1.2.3.value1", "A dynamic value 1");
		userData.getExtendedinformation().setExtensionData("1.2.3.value2", "A dynamic value 2");
		userData.getExtendedinformation().setExtensionData("1.2.3.value3", "A dynamic value 3");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		value = in.readObject();
		assertTrue(value.getClass().toString(),value instanceof DERSequence);
		seq = (DERSequence)value;
		assertEquals(3, seq.size());
		e = seq.getObjects();
		i = 1;
		while (e.hasMoreElements()) {
			DEREncodable v = (DEREncodable)e.nextElement();
			assertTrue(v.getClass().toString(), v instanceof DERPrintableString);
			String str = ((DERPrintableString) v).getString();
			assertEquals(str, "A dynamic value " + i++);        
		}
	}
	
	/**
	 * Test that without dynamic specified it defaults to dynamic=false.
	 *
	 * The static value should be used regardless of there was a value in 
	 * ExtendedInformation or not.
	 */
	public void test16DynamicDefaultsToFalse() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "The static value");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Ok without value specified
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value1).getString());
		
		// Ignoring dynamic value specified
		userData.getExtendedinformation().setExtensionData("1.2.3", "The value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value1).getString());
	}
	
	/**
	 * Same as test16DynamicDefaultsToFalse but with dynamic explicitly set to
	 *  false.
	 */
	public void test17DynamicFalse() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.value", "The static value");
		props.put("id1.property.dynamic", "false");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Ok without value specified
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value = in.readObject();
		assertTrue(value.getClass().toString(), value instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value).getString());
		
		// Ignoring dynamic value specified
		userData.getExtendedinformation().setExtensionData("1.2.3", "The value 123");
		in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		value = in.readObject();
		assertTrue(value.getClass().toString(), value instanceof DERPrintableString);
		assertEquals("The static value", ((DERPrintableString) value).getString());
	}
	
	/**
	 * Test with dynamic=true and value specified with key 1.2.3.value=.
	 */
	public void test18DynamicValueValue() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERPRINTABLESTRING");
		props.put("id1.property.dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Success with value specified
		userData.getExtendedinformation().setExtensionData("1.2.3.value", "The value 456");
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(baseExt.getValueEncoded(userData, null, null, null, null)));
		DEREncodable value1 = in.readObject();
		assertTrue(value1.getClass().toString(), value1 instanceof DERPrintableString);
		assertEquals("The value 456", ((DERPrintableString) value1).getString());
	}
	
        /**
         * Test using encoding=RAW and both dynamic and static value.
         */
	public void test19RawValue() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "RAW");
		props.put("id1.property.dynamic", "true");
		props.put("id1.property.value", "aabbccdd");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Without value in userdata, the static value is used
		byte[] value = baseExt.getValueEncoded(userData, null, null, null, null);
		assertEquals("value", "aabbccdd", new String(Hex.encode(value)));
		
		// With value in userdata, that value is used
		userData.getExtendedinformation().setExtensionData("1.2.3", "eeff0000");
		value = baseExt.getValueEncoded(userData, null, null, null, null);
		assertEquals("value", "eeff0000", new String(Hex.encode(value)));
	}
        
        /**
         * Test using encoding=RAW and only dynamic value.
         */
	public void test21RawValueNotSpecified() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "RAW");
		props.put("id1.property.dynamic", "true");
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
		// Without value in userdata it should fail
                try {
                    byte[] value = baseExt.getValueEncoded(userData, null, null, null, null);
                    fail("Should have fail as no dynamic value specified");
                } catch (CertificateExtentionConfigurationException ex) {
                    assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
                }
		
		// With value in userdata, that value is used
		userData.getExtendedinformation().setExtensionData("1.2.3", "eeff0000");
		byte[] value = baseExt.getValueEncoded(userData, null, null, null, null);
		assertEquals("value", "eeff0000", new String(Hex.encode(value)));
	}
        
        /**
         * Test without any value specified.
         */
        public void test22ValueNotSpecified() throws Exception{
		Properties props = new Properties();
		props.put("id1.property.encoding", "DERINTEGER");
		
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		
                try {
                    baseExt.getValueEncoded(null, null, null, null, null);
                    fail("Should have fail as no value specified");
                } catch (CertificateExtentionConfigurationException ex) {
                    assertEquals(intres.getLocalizedMessage("certext.basic.incorrectvalue", 1, "1.2.3"), ex.getMessage());
                }
	}
        
        /**
         * Test using encoding=RAW but nvalues > 1 specified which is a
         * configuration error.
         */
	public void test23RawValueButNValues() throws Exception {
		Properties props = new Properties();
		props.put("id1.property.encoding", "RAW");
		props.put("id1.property.dynamic", "true");
                props.put("id1.property.nvalues", "3"); 
		props.put("id1.property.value1", "foo1");
		props.put("id1.property.value2", "foo2");
		props.put("id1.property.value3", "foo3");
                
		BasicCertificateExtension baseExt = new BasicCertificateExtension();
		baseExt.init(1, "1.2.3", false, props);
		UserDataVO userData = new UserDataVO();
		userData.setExtendedinformation(new ExtendedInformation());
		
                try {
                    byte[] value = baseExt.getValueEncoded(userData, null, null, null, null);
                    fail("Should have fail as both raw and nvalues specified");
                } catch (CertificateExtentionConfigurationException ex) {
                    assertEquals(intres.getLocalizedMessage("certext.certextmissconfigured", 1), ex.getMessage());
                }
	}

	private DEREncodable getObject(byte[] valueEncoded) throws IOException {
		ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(valueEncoded));
		return in.readObject();
	}	
}
