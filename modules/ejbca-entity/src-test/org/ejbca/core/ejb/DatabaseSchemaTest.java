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

package org.ejbca.core.ejb;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.authorization.AccessRulesData;
import org.ejbca.core.ejb.authorization.AdminEntityData;
import org.ejbca.core.ejb.authorization.AdminGroupData;
import org.ejbca.core.ejb.ca.caadmin.CAData;
import org.ejbca.core.ejb.ca.caadmin.CertificateProfileData;
import org.ejbca.core.ejb.ca.publisher.PublisherData;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.ejb.ca.store.CertReqHistoryData;
import org.ejbca.core.ejb.ca.store.CertificateData;
import org.ejbca.core.ejb.hardtoken.HardTokenCertificateMap;
import org.ejbca.core.ejb.hardtoken.HardTokenData;
import org.ejbca.core.ejb.hardtoken.HardTokenIssuerData;
import org.ejbca.core.ejb.hardtoken.HardTokenProfileData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyDataPK;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataPK;
import org.ejbca.core.ejb.log.LogConfigurationData;
import org.ejbca.core.ejb.log.LogEntryData;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationData;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceData;
import org.ejbca.core.ejb.services.ServiceData;
import org.ejbca.core.model.log.LogConfiguration;

/**
 * Simple class to trigger Hibernate's JPA schema validation.
 * 
 * We also validate that all fields can hold the values that we assume they can.
 * 
 * @version $Id: DatabaseSchemaTest.java 11396 2011-02-23 16:22:31Z jeklund $
 */
public class DatabaseSchemaTest extends TestCase {
	
	private static final Logger LOG = Logger.getLogger(DatabaseSchemaTest.class);

	private static String VARCHAR_80B;
	private static String VARCHAR_250B;
	private static String CLOB_10KiB;
	private static String CLOB_100KiB;
	private static String CLOB_1MiB;
	private static final HashMap HASHMAP_200K = new HashMap();
	private static final HashMap HASHMAP_1M = new HashMap();
	private static final int BOGUS_INT = -32;	// Very random..
	private static final Integer BOGUS_INTEGER = Integer.valueOf(BOGUS_INT);
	private static EntityManagerFactory entityManagerFactory;
	private static EntityManager entityManager;
	
	@Override
	public void setUp() throws Exception {
		super.setUp();
		LOG.trace(">setup");
		if (entityManagerFactory == null) {
			entityManagerFactory = Persistence.createEntityManagerFactory("ejbca-pu");
		}
		entityManager = entityManagerFactory.createEntityManager();
		LOG.trace("<setup");
	}
	
	@Override
	public void tearDown() throws Exception {
		super.tearDown();
		LOG.trace(">tearDown");
		entityManager.close();
		LOG.trace("<tearDown");
	}

	public void test000Setup() throws Exception {
		LOG.trace(">test000Setup");
		logMemStats();
		LOG.debug("Allocating memory..");
		VARCHAR_80B = getClob(80);
		VARCHAR_250B = getClob(250);
		CLOB_10KiB = getClob(10*1024);
		CLOB_100KiB = getClob(100*1024);
		CLOB_1MiB = getClob(1024*1024);
		LOG.debug("Filling HashMaps..");
		HASHMAP_200K.put("object", getLob(196*1024));	// It need to be less than 200KiB in Serialized format..
		HASHMAP_1M.put("object", getLob(996*1024));		// It need to be less than 1MiB in Serialized format.. 
		logMemStats();
		LOG.trace("<test000Setup");
	}
	
	private byte[] getLob(int size) {
		byte[] ret = new byte[size];
		Arrays.fill(ret, (byte) '0');
		return ret;
	}

	private String getClob(int size) {
		return new String(getLob(size));
	}

	public void testApprovalData() {
		LOG.trace(">testApprovalData");
		logMemStats();
		ApprovalData entity = new ApprovalData();
		entity.setApprovalid(0);
		entity.setApprovaldata(CLOB_1MiB);
		entity.setApprovaltype(0);
		entity.setCaid(0);
		entity.setEndentityprofileid(0);
		entity.setExpiredate(0);
		entity.setId(Integer.valueOf(0));
		entity.setRemainingapprovals(0);
		entity.setReqadmincertissuerdn(VARCHAR_250B);
		entity.setReqadmincertsn(VARCHAR_250B);
		entity.setRequestdata(CLOB_1MiB);
		entity.setRequestdate(0);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setStatus(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testApprovalData");
	}

	public void testAccessRulesData() {
		LOG.trace(">testAccessRulesData");
		logMemStats();
		AccessRulesData entity = new AccessRulesData();
		entity.setAccessRule(VARCHAR_250B);
		entity.setIsRecursive(false);
		entity.setPrimKey(BOGUS_INTEGER.intValue());
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setRule(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testAccessRulesData");
	}

	public void testAdminEntityData() {
		LOG.trace(">testAdminEntityData");
		logMemStats();
		AdminEntityData entity = new AdminEntityData();
		entity.setCaId(BOGUS_INTEGER);
		entity.setMatchType(0);
		entity.setMatchValue(VARCHAR_250B);
		entity.setMatchWith(0);
		entity.setPrimeKey(BOGUS_INT);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testAdminEntityData");
	}

	public void testAdminGroupData() {
		LOG.trace(">testAdminGroupData");
		logMemStats();
		AdminGroupData entity = new AdminGroupData();
		entity.setAdminGroupName(VARCHAR_250B);
		entity.setCaId(BOGUS_INT);
		entity.setPrimeKey(BOGUS_INTEGER);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testAdminGroupData");
	}

	public void testCAData() {
		LOG.trace(">testCAData");
		logMemStats();
		CAData entity = new CAData();
		entity.setCaId(BOGUS_INTEGER);
		entity.setData(CLOB_100KiB);
		entity.setExpireTime(0);
		entity.setName(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setStatus(0);
		entity.setSubjectDN(VARCHAR_250B);
		entity.setUpdateTime(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testCAData");
	}

	public void testCertificateProfileData() {
		LOG.trace(">testCertificateProfileData");
		logMemStats();
		CertificateProfileData entity = new CertificateProfileData();
		entity.setCertificateProfileName(VARCHAR_250B);
		entity.setDataUnsafe(HASHMAP_1M);
		entity.setId(BOGUS_INTEGER);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testCertificateProfileData");
	}

	public void testPublisherData() {
		LOG.trace(">testPublisherData");
		logMemStats();
		PublisherData entity = new PublisherData();
		entity.setData(CLOB_100KiB);
		entity.setId(BOGUS_INTEGER);
		entity.setName(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setUpdateCounter(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testPublisherData");
	}

	public void testPublisherQueueData() {
		LOG.trace(">testPublisherQueueData");
		logMemStats();
		PublisherQueueData entity = new PublisherQueueData();
		entity.setFingerprint(VARCHAR_250B);
		entity.setLastUpdate(0);
		entity.setPk(VARCHAR_250B);
		entity.setPublisherId(0);
		entity.setPublishStatus(0);
		entity.setPublishType(0);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setTimeCreated(0);
		entity.setTryCounter(0);
		entity.setVolatileData(CLOB_100KiB);
		storeAndRemoveEntity(entity);
		LOG.trace("<testPublisherQueueData");
	}

	public void testCertificateData() {
		LOG.trace(">testCertificateData");
		logMemStats();
		CertificateData entity = new CertificateData();
		entity.setBase64Cert(CLOB_1MiB);
		entity.setCaFingerprint(VARCHAR_250B);
		entity.setCertificateProfileId(BOGUS_INTEGER);
		entity.setExpireDate(0L);
		entity.setFingerprint(VARCHAR_250B);
		entity.setIssuerDN(VARCHAR_250B);
		//setPrivateField(entity, "issuerDN", VARCHAR_250B);
		entity.setRevocationDate(0L);
		entity.setRevocationReason(0);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setSerialNumber(VARCHAR_250B);
		entity.setStatus(0);
		entity.setSubjectDN(VARCHAR_250B);
		//setPrivateField(entity, "subjectDN", VARCHAR_250B);
		entity.setSubjectKeyId(VARCHAR_250B);
		entity.setTag(VARCHAR_250B);
		entity.setType(0);
		entity.setUpdateTime(Long.valueOf(0L));
		entity.setUsername(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testCertificateData");
	}

	public void testCertReqHistoryData() {
		LOG.trace(">testCertReqHistoryData");
		logMemStats();
		CertReqHistoryData entity = new CertReqHistoryData();
		entity.setIssuerDN(VARCHAR_250B);
		entity.setFingerprint(VARCHAR_250B);
		//setPrivateField(entity, "issuerDN", VARCHAR_250B);
		//setPrivateField(entity, "fingerprint", VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setSerialNumber(VARCHAR_250B);
		//setPrivateField(entity, "serialNumber", VARCHAR_250B);
		entity.setTimestamp(0L);
		entity.setUserDataVO(CLOB_1MiB);
		entity.setUsername(VARCHAR_250B);
		//setPrivateField(entity, "username", VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testCertReqHistoryData");
	}

	// ZZ to run this test last, since we often run out of memory here and mess up the database connection.
	public void testZZCRLData() {
		LOG.trace(">testCRLData");
		logMemStats();
		String CLOB_100MiB = getClob(100*1024*1024);
		CRLData entity = new CRLData();
		entity.setBase64Crl(CLOB_100MiB);
		CLOB_100MiB = null;
		System.gc();
		entity.setCaFingerprint(VARCHAR_250B);
		entity.setCrlNumber(0);
		entity.setDeltaCRLIndicator(0);
		entity.setFingerprint(VARCHAR_250B);
		entity.setIssuerDN(VARCHAR_250B);
		//setPrivateField(entity, "issuerDN", VARCHAR_250B);
		entity.setNextUpdate(0L);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setThisUpdate(0L);
		storeAndRemoveEntity(entity);
		LOG.trace("<testCRLData");
	}

	public void testHardTokenCertificateMap() {
		LOG.trace(">testHardTokenCertificateMap");
		logMemStats();
		HardTokenCertificateMap entity = new HardTokenCertificateMap();
		entity.setCertificateFingerprint(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setTokenSN(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testHardTokenCertificateMap");
	}

	public void testHardTokenData() {
		LOG.trace(">testHardTokenData");
		logMemStats();
		HardTokenData entity = new HardTokenData();
		entity.setCtime(0L);
		entity.setData(HASHMAP_200K);
		entity.setMtime(0L);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setSignificantIssuerDN(VARCHAR_250B);
		entity.setTokenSN(VARCHAR_250B);
		entity.setTokenType(0);
		entity.setUsername(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testHardTokenData");
	}

	public void testHardTokenIssuerData() {
		LOG.trace(">testHardTokenIssuerData");
		logMemStats();
		HardTokenIssuerData entity = new HardTokenIssuerData();
		entity.setAdminGroupId(0);
		entity.setAlias(VARCHAR_250B);
		entity.setDataUnsafe(HASHMAP_200K);
		entity.setId(BOGUS_INTEGER);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testHardTokenIssuerData");
	}

	public void testHardTokenProfileData() {
		LOG.trace(">testHardTokenProfileData");
		logMemStats();
		HardTokenProfileData entity = new HardTokenProfileData();
		entity.setData(CLOB_1MiB);
		entity.setId(BOGUS_INTEGER);
		entity.setName(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setUpdateCounter(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testHardTokenProfileData");
	}

	public void testHardTokenPropertyData() {
		LOG.trace(">testHardTokenPropertyData");
		logMemStats();
		HardTokenPropertyData entity = new HardTokenPropertyData();
		// Combined primary key id+property has to be less than 1000 bytes on MyISAM (UTF8: 3*(80+250) < 1000 bytes)
		entity.setHardTokenPropertyDataPK(new HardTokenPropertyDataPK(VARCHAR_80B, VARCHAR_250B));
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setValue(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testHardTokenPropertyData");
	}

	public void testKeyRecoveryData() {
		LOG.trace(">testKeyRecoveryData");
		logMemStats();
		KeyRecoveryData entity = new KeyRecoveryData();
		entity.setKeyRecoveryDataPK(new KeyRecoveryDataPK(VARCHAR_80B, VARCHAR_250B));
		entity.setKeyData(CLOB_1MiB);
		entity.setMarkedAsRecoverable(false);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setUsername(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testKeyRecoveryData");
	}

	public void testLogConfigurationData() {
		LOG.trace(">testLogConfigurationData");
		logMemStats();
		LogConfigurationData entity = new LogConfigurationData();
		entity.setId(BOGUS_INTEGER);
		entity.setLogConfigurationUnsafe(new LogConfiguration(false, false, HASHMAP_200K));
		entity.setLogEntryRowNumber(0);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testLogConfigurationData");
	}

	public void testLogEntryData() {
		LOG.trace(">testLogEntryData");
		logMemStats();
		LogEntryData entity = new LogEntryData();
		entity.setAdminData(VARCHAR_250B);
		entity.setAdminType(0);
		entity.setCaId(0);
		entity.setCertificateSNR(VARCHAR_250B);
		entity.setEvent(0);
		entity.setId(BOGUS_INTEGER);
		entity.setLogComment(VARCHAR_250B);
		entity.setModule(0);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setTime(0L);
		entity.setUsername(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testLogEntryData");
	}

	public void testUserData() {
		LOG.trace(">testUserData");
		logMemStats();
		UserData entity = new UserData();
		entity.setCaId(0);
		entity.setCardNumber(VARCHAR_250B);
		entity.setCertificateProfileId(0);
		entity.setClearPassword(VARCHAR_250B);
		entity.setEndEntityProfileId(0);
		entity.setExtendedInformationData(CLOB_1MiB);
		entity.setHardTokenIssuerId(0);
		entity.setKeyStorePassword(VARCHAR_250B);
		entity.setPasswordHash(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setStatus(0);
		entity.setSubjectAltName(VARCHAR_250B);
		entity.setSubjectDN(VARCHAR_250B);
		entity.setSubjectEmail(VARCHAR_250B);
		entity.setTimeCreated(0L);
		entity.setTimeModified(0L);
		entity.setTokenType(0);
		entity.setType(0);
		entity.setUsername(VARCHAR_250B);
		storeAndRemoveEntity(entity);
		LOG.trace("<testUserData");
	}

	public void testAdminPreferencesData() {
		LOG.trace(">testAdminPreferencesData");
		logMemStats();
		AdminPreferencesData entity = new AdminPreferencesData();
		entity.setDataUnsafe(HASHMAP_200K);
		entity.setId(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testAdminPreferencesData");
	}

	public void testEndEntityProfileData() {
		LOG.trace(">testEndEntityProfileData");
		logMemStats();
		EndEntityProfileData entity = new EndEntityProfileData();
		entity.setDataUnsafe(HASHMAP_200K);
		entity.setId(BOGUS_INTEGER);
		entity.setProfileName(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testEndEntityProfileData");
	}

	public void testGlobalConfigurationData() {
		LOG.trace(">testGlobalConfigurationData");
		logMemStats();
		GlobalConfigurationData entity = new GlobalConfigurationData();
		entity.setConfigurationId(VARCHAR_250B);
		entity.setDataUnsafe(HASHMAP_200K);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testGlobalConfigurationData");
	}

	public void testUserDataSourceData() {
		LOG.trace(">testUserDataSourceData");
		logMemStats();
		UserDataSourceData entity = new UserDataSourceData();
		entity.setData(CLOB_100KiB);
		entity.setId(BOGUS_INTEGER);
		entity.setName(VARCHAR_250B);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setUpdateCounter(0);
		storeAndRemoveEntity(entity);
		LOG.trace("<testUserDataSourceData");
	}

	public void testServiceData() {
		LOG.trace(">testServiceData");
		logMemStats();
		ServiceData entity = new ServiceData();
		entity.setData(CLOB_100KiB);
		entity.setId(BOGUS_INTEGER);
		entity.setName(VARCHAR_250B);
		entity.setNextRunTimeStamp(0L);
		entity.setRowProtection(CLOB_10KiB);
		entity.setRowVersion(0);
		entity.setRunTimeStamp(0L);
		storeAndRemoveEntity(entity);
		LOG.trace("<testServiceData");
	}
	
	public void testZZZCleanUp() throws Exception {
		LOG.trace(">testZZZCleanUp");
		entityManagerFactory.close();
		logMemStats();
		LOG.trace("<testZZZCleanUp");
	}

	/**
	 * Outputs which method it is run from.
	 * Validates that all getters on the entity that is annotated with @javax.persistence.Column is set. 
	 * Commits the entity in one transaction and then removes it in another transaction.
	 */
	private void storeAndRemoveEntity(Object entity) {
		LOG.trace(">storeAndRemoveEntity");
		logMemStats();
		try {
			Class<?> entityClass = entity.getClass();
			LOG.info("  - verifying that all getter has an assigned value for " + entityClass.getName());
			boolean allOk = true;
			for (Method m : entityClass.getDeclaredMethods()) {
				for (Annotation a :m.getAnnotations()) {
					if (a.annotationType().equals(javax.persistence.Column.class) && m.getName().startsWith("get")) {
						try {
							m.setAccessible(true);
							if (m.invoke(entity) == null) {
								LOG.warn(m.getName() + " was annotated with @Column, but value was null. Test should be updated!");
								allOk = false;
							}
						} catch (Exception e) {
							LOG.error(m.getName() + " was annotated with @Column and could not be read. " + e.getMessage());
							allOk = false;
						}
					}
				}
			}
			assertTrue("There is a problem with a @Column annotated getter. Please refer to log output for further info.", allOk);
			LOG.info("  - adding entity.");
			EntityTransaction transaction = entityManager.getTransaction();
			transaction.begin();
			entityManager.persist(entity);
			transaction.commit();
			LOG.info("  - removing entity.");
			transaction = entityManager.getTransaction();
			transaction.begin();
			entityManager.remove(entity);
			transaction.commit();
		} finally {
			if (entityManager.getTransaction().isActive()) {
				entityManager.getTransaction().rollback();
			}
			logMemStats();
		}
		LOG.trace("<storeAndRemoveEntity");
	}
	
	private void logMemStats() {
		System.gc();
		final long maxMemory = Runtime.getRuntime().maxMemory() / 1024 /1024;
		final long freeMemory = Runtime.getRuntime().freeMemory() / 1024 /1024;
		LOG.info("JVM Runtime reports: freeMemory="+freeMemory+"MiB, maxMemory="+maxMemory+"MiB, (" + (maxMemory-freeMemory)*100/maxMemory + "% used)");
	}
	
	/* * Used in order to bypass validity check of different private fields that are access via transient setters. * /
	private void setPrivateField(Object entity, String fieldName, Object value) {
		LOG.trace(">setPrivateField");
		try {
			Field field = entity.getClass().getDeclaredField(fieldName);
			field.setAccessible(true);
			field.set(entity, value);
		} catch (Exception e) {
			LOG.error("", e);
			assertTrue("Could not set " + fieldName + " to " + value + ": " + e.getMessage(), false);
		}
		LOG.trace("<setPrivateField");
	}
	*/
}
