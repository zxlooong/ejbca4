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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.util.Collection;


/**
 * Class representing an Worker Type, should be registered in the 
 * ServiceTypesManager. Should be inherited by all worker managed beans.
 * 
 * Defines which actions and interval that are compatible with this worker
 *
 * @version $Id: WorkerType.java 15089 2012-07-02 15:09:55Z mikekushner $
 */
public abstract class WorkerType extends ServiceType {

	public WorkerType(String subViewPage, String name, boolean translatable) {
		super(subViewPage, name, translatable);
	}

	/**
	 * @return the names of the Compatible Action Types
	 */
	public abstract Collection getCompatibleActionTypeNames();

	/**
	 * @return the names of the Compatible Interval Types
	 */
	public abstract Collection getCompatibleIntervalTypeNames();

}
