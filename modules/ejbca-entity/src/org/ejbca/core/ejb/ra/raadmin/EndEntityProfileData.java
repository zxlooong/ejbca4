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
 
package org.ejbca.core.ejb.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JBossUnmarshaller;
import org.ejbca.core.ejb.QueryResultWrapper;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Representation of an End Entity Profile.
 * 
 * @version $Id: EndEntityProfileData.java 11670 2011-04-01 15:16:11Z jeklund $
 */ 
@Entity
@Table(name="EndEntityProfileData")
public class EndEntityProfileData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(EndEntityProfileData.class);

	private int id;
	private String profileName;
	private Serializable data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a end entity profile.
	 */
	public EndEntityProfileData(int id, String profileName, EndEntityProfile endEntityProfile) {
		setId(id);
		setProfileName(profileName);
		setProfile(endEntityProfile);
		log.debug("Created profile " + profileName);
	}
	
	public EndEntityProfileData() { }

	//@Id @Column
	public int getId() { return id; }
	public void setId(int id) { this.id = id; }

	//@Column
	public String getProfileName() { return profileName; }
	public void setProfileName(String profileName) { this.profileName = profileName; }

	//@Column @Lob
	public Serializable getDataUnsafe() { return data; }
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	public void setDataUnsafe(Serializable data) { this.data = data; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	private HashMap getData() { return JBossUnmarshaller.extractObject(HashMap.class, getDataUnsafe()); }
	private void setData(HashMap data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

    /**
     * Method that returns the end entity profile and updates it if necessary.
     */
	@Transient
    public EndEntityProfile getProfile() {
    	return readAndUpgradeProfileInternal();
    }

    /**
     * Method that saves the end entity profile.
     */
    public void setProfile(EndEntityProfile profile) {
        setData((HashMap) profile.saveData());
    }

    /** 
     * Method that upgrades a EndEntity Profile, if needed.
     */
    public void upgradeProfile() {
    	readAndUpgradeProfileInternal();
    }

    /**
     * We have an internal method for this read operation with a side-effect. 
     * This is because getProfile() is a read-only method, so the possible side-effect of upgrade will not happen,
     * and therefore this internal method can be called from another non-read-only method, upgradeProfile().
     * @return EndEntityProfile
     * TODO: Still true with JPA?
     */
    private EndEntityProfile readAndUpgradeProfileInternal() {
        EndEntityProfile returnval = new EndEntityProfile(0);
        HashMap data = getData();
        // If EndEntityProfile-data is upgraded we want to save the new data, so we must get the old version before loading the data 
        // and perhaps upgrading
        float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
        // Load the profile data, this will potentially upgrade the CertificateProfile
        returnval.loadData(data);
        if (Float.compare(oldversion, returnval.getVersion()) != 0) {
        	// Save new data versions differ
        	setProfile(returnval);
        	if (log.isDebugEnabled()) {
            	log.debug("Saved upgraded profile, old version="+oldversion+", new version="+returnval.getVersion());        		
        	}
        }
        return returnval;
    }

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static EndEntityProfileData findById(EntityManager entityManager, int id) {
		return entityManager.find(EndEntityProfileData.class, id);
	}
	
	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static EndEntityProfileData findByProfileName(EntityManager entityManager, String profileName) {
		Query query = entityManager.createQuery("SELECT a FROM EndEntityProfileData a WHERE a.profileName=:profileName");
		query.setParameter("profileName", profileName);
		return (EndEntityProfileData) QueryResultWrapper.getSingleResult(query);
	}

	/** @return return the query results as a List. */
	public static List<EndEntityProfileData> findAll(EntityManager entityManager) {
		Query query = entityManager.createQuery("SELECT a FROM EndEntityProfileData a");
		return query.getResultList();
	}
}
