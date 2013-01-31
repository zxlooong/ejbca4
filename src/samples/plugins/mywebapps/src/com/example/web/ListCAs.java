package com.example.web;

import java.io.IOException;

import javax.ejb.EJB;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import org.ejbca.core.model.log.Admin;

import org.ejbca.core.ejb.ca.caadmin.CaSessionLocal;
/**
 * This is a demo servlet that list all CAs in the system
 */
public class ListCAs extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final static Logger log = Logger.getLogger(ListCAs.class);

    @EJB
    private CaSessionLocal caSession;
    
    /**
     * This is a demo servlet that list all CAs in the system
     */
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        StringBuffer out = new StringBuffer ("<html><body><h3>List CAs</h3>");
        Admin admin = new Admin(Admin.TYPE_INTERNALUSER, request.getRemoteAddr());
        for (Integer caid : caSession.getAvailableCAs(admin)) {
        	try {
        		out.append("<br>").append(caSession.getCA(admin, caid).getName());
        	} catch (Exception e) {
        		throw new IOException (e);
        	}
        }
        out.append("</body></html>");
        response.getOutputStream ().print (out.toString ());
        log.info("Listed a few CAs...");
    } // doGet

}
