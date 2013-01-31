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

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Helper class for extracting objects Serialized on JBoss under J2EE.
 * 
 * Used during upgrade from EJBCA 3.11.x to EJBCA 4.0.y.
 * 
 * @version $Id: JBossUnmarshaller.java 12655 2011-09-21 12:55:56Z anatom $
 */
public final class JBossUnmarshaller {
	
	private static final Logger LOG = Logger.getLogger(JBossUnmarshaller.class);
	private static final String JBOSS_MARSHALL_CLASS = "org.jboss.invocation.MarshalledValue";
	private static boolean lookForJbossMarshaller = true;

	private JBossUnmarshaller() {}

	/**
	 * Helper method for extracting objects Serialized on JBoss under J2EE.
	 * 
	 * The methods uses the fact that org.jboss.invocation.MarshalledValue is also a Serializable object
	 * and extracts the real object from the MarshalledValue if this is passed as a parameter.
	 * Otherwise the object is returned in it's current form.
	 * 
	 * @param <T>  Class that we are trying to extract.
	 * @param t  Class that we are trying to extract.
	 * @param object An object implementing java.lang.Serializable interface
	 * @return The unmarshalled or original object of type T
	 */
	public static <T> T extractObject(final Class<T> t, final Serializable object) {
		T ret = null;
		final String className = object.getClass().getName();
		if (className.equals(t.getName())) {
			ret = (T) object;
		} else if (JBOSS_MARSHALL_CLASS.equals(className)) {
			try {
				final Method m = object.getClass().getMethod("get", new Class[0]);
				ret = (T) m.invoke(object, new Object[0]);
			} catch (Exception e) {
				LOG.error("", e);
			}
		} else if (className.equals(org.cesecore.util.Base64GetHashMap.class.getName())) {
			// Make special handling if this is an EJBCA 5.0 that has been downgraded to 4.0 (rollback after upgrade perhaps)
			if (LOG.isTraceEnabled()) {
				LOG.trace("Converting from cesecore Base64GetHashMap to older EJBCA Base64GetHashMap, this is a downgraded EJBCA 5 to EJBCA 4.");
			}
			if (t.getName().equals(org.ejbca.util.Base64GetHashMap.class.getName()) || t.getName().equals(HashMap.class.getName())) {
				ret = (T)new org.ejbca.util.Base64GetHashMap((org.cesecore.util.Base64GetHashMap)object);
			} else {
				LOG.error("Can not convert from org.cesecore.util.Base64GetHashMap to "+t.getName());
			}
		} else if (LinkedHashMap.class.getName().equals(object.getClass().getName()) && t.getName().equals(HashMap.class.getName())) {
			// If we have a LinkedHashMap (ejbca5) in the database, and tries to read a HashMap (ejbca4)
			ret = (T)object;
		} else {
			LOG.error("Extraction from " + className + " is currently not supported");
		}
		return ret;
	}

	/**
	 * During upgrade from EJBCA 3.11.x to EJBCA 4.0.x on a 100% up-time cluster, we will have
	 * old EJB 2.1 CMP serialization on JBoss installations together with new EJB 3.0 JPA pure
	 * Java serialization.
	 * 
	 * Until all nodes has been upgraded, we have to keep storing things as before, to not break
	 * the old installations.
	 *   
	 * @param object is the object that will be stored as a BLOB
	 * @return either the pure object or a JBoss serialized version of the Object
	 */
	public static Serializable serializeObject(final Serializable object) {
		Serializable ret = object;
		if (lookForJbossMarshaller && EjbcaConfiguration.getEffectiveApplicationVersion() == 311) {
			try {
				// Do "ret = new org.jboss.invocation.MarshalledValue(object)" with inflection, since we can't know
				// if we are running on a JBoss AS or not.
				ret = (Serializable) Class.forName(JBOSS_MARSHALL_CLASS).getConstructor(Object.class).newInstance(object);
			} catch (ClassNotFoundException e1) {
				LOG.debug(JBOSS_MARSHALL_CLASS + " does not exist. Assuming that this is a non-JBoss installation.");
				lookForJbossMarshaller = false;	// Can only go from true to false, so there is no need for synchronization
			} catch (Exception e) {
				LOG.error("Unable to store as JBoss MarshalledValue.", e);
			}
		}
		return ret;
	}
}
