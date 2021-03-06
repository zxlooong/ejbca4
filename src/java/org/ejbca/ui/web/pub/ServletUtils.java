package org.ejbca.ui.web.pub;

import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

/** 
 * A class containing some helpful functions used in more than one Servlet, avoiding code duplication.
 * 
 * @author tomasg
 * @version $Id: ServletUtils.java 9508 2010-07-22 23:13:44Z jeklund $
 */
public class ServletUtils {

    private static Logger log = Logger.getLogger(ServletUtils.class);

    /** Helper methods that removes no-cache headers from a response. No-cache headers 
     * makes IE refuse to save a file that is sent (for example a certificate). 
     * No-cache headers are also automatically added by Tomcat by default, so we better
     * make sure they are set to a harmless value.
     * 
     * @param res HttpServletResponse parameter as taken from the doGet, doPost methods in a Servlet.
     */
    public static void removeCacheHeaders(HttpServletResponse res) {
        if (res.containsHeader("Pragma")) {
            log.debug("Removing Pragma header to avoid caching issues in IE");
            res.setHeader("Pragma","null");
        }
        if (res.containsHeader("Cache-Control")) {
            log.debug("Removing Cache-Control header to avoid caching issues in IE");
            res.setHeader("Cache-Control","null");
        }
    }

    /** Helper methods that adds no-cache headers to a response. 
     * 
     * @param res HttpServletResponse parameter as taken from the doGet, doPost methods in a Servlet.
     */
    public static void addCacheHeaders(HttpServletResponse res) {
        if (!res.containsHeader("Pragma")) {
            log.debug("Adding Pragma header");
            res.setHeader("Pragma","no-cache");
        }
        if (!res.containsHeader("Cache-Control")) {
            log.debug("Adding Cache-Control header");
            res.setHeader("Cache-Control","no-cache");
        }
    }
}
