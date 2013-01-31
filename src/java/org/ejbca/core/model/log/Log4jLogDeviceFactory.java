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

package org.ejbca.core.model.log;



/**
 * Factory for Log4j log device.
 *
 * @version $Id: Log4jLogDeviceFactory.java 8028 2009-09-25 17:20:37Z jeklund $
 */
public class Log4jLogDeviceFactory {
    /**
     * Creates a new Log4jLogDeviceFactory object.
     */
    public Log4jLogDeviceFactory() {
    }

    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @return An instance of the log device.
     */
    public synchronized ILogDevice makeInstance(String name)
            throws Exception {
        return Log4jLogDevice.instance(name);
    }
}
