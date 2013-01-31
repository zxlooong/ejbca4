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
 
package org.ejbca.core.protocol.ws.client;

import org.ejbca.core.protocol.ws.client.gen.EjbcaException;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.IAdminCommand;

/**
 * Implements the EJBCA RA WS command line interface
 *
 * @version $Id: cmpnestedmessagetest.java 15009 2012-06-18 12:49:30Z primelars $
 */
public class cmpnestedmessagetest  {
    /**
     * main Client
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: crmfrequest | missingstoredcert | wrongsignature");
            }
        } catch (Exception e) {
        	Throwable cause = e.getCause();
        	if (cause instanceof EjbcaException_Exception) {
        		EjbcaException_Exception ejbcaex = (EjbcaException_Exception)cause;
        		EjbcaException ee = ejbcaex.getFaultInfo();
        		System.out.println("Error: "+ee.getErrorCode().getInternalErrorCode()+": "+ee.getMessage());
			} else {
	            System.out.println(e.getMessage());
			}
            e.printStackTrace();				
            System.exit(-1); // NOPMD, this is not a JEE app
        }
    }
    
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1) {
            return null;
        }        
        
        if (args[0].equals("crmfrequest")) {
            return new NestedCrmfRequestTestCommand(args);
        }else if (args[0].equals("missingstoredcert")) {
            return new NestedCrmfRequestMissingStoredCertTestCommand(args);
        }else if (args[0].equals("wrongsignature")) {
            return new NestedCrmfRequestWrongSignatureTestCommand(args);
            /*
        } else if (args[0].equals("stress")) {
            return new StressTestCommand(args);
        */
	    }
        
        else {
            return null;
        }
    }
}
