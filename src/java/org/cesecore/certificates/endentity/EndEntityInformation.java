/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.endentity;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;

import org.cesecore.util.Base64GetHashMap;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64PutHashMap;
import org.ejbca.util.StringTools;
import org.ejbca.util.dn.DNFieldsUtil;


/**
 * Holds admin data collected from UserData in the database. Strings are stored in Base64 encoded format to be safe for storing in database, xml etc.
 *
 * Forwards compatibility class with EJBCA 5.0
 * 
 * @version $Id: EndEntityInformation.java 12818 2011-10-05 08:10:53Z primelars $
 */
public class EndEntityInformation implements Serializable {

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = 3837505643343885941L;

    // Public constants
    public static final int NO_ENDENTITYPROFILE    = 0;
    public static final int NO_CERTIFICATEPROFILE  = 0;


    private String username;
    private String subjectDN;
    transient private String subjectDNClean = null;
    private int caid;
    private String subjectAltName;
    private String subjectEmail;
    private String password;
    private String cardNumber;
    /** Status of user, from {@link EndEntityConstants#STATUS_NEW} etc*/
    private int status;
    /** Type of user, from {@link EndEntityConstants#USER_ENDUSER} etc*/
    private int type;
    private int endentityprofileid;
    private int certificateprofileid;
    private Date timecreated;
    private Date timemodified;
    /** Type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc*/
    private int tokentype;
    private int hardtokenissuerid;
    private ExtendedInformation extendedinformation;

    /** Creates new empty EndEntityInformation */
    public EndEntityInformation() {
    }

    /**
     * Creates new EndEntityInformation. All fields are almost required in this constructor. Password must
     * be set manually though. This is so you should be sure what you do with the password.
     *
     * @param user DOCUMENT ME!
     * @param dn DOCUMENT ME!
     * @param caid CA id of the CA that the user is registered with
     * @param subjectaltname DOCUMENT ME!
     * @param email DOCUMENT ME!
     * @param status Status of user, from {@link EndEntityConstants#STATUS_NEW} etc
     * @param type Type of user, from {@link EndEntityConstants#USER_ENDUSER} etc, can be "ored" together, i.e. EndEntityConstants#USER_ENDUSER | {@link EndEntityConstants#USER_SENDNOTIFICATION}
     * @param endentityprofileid DOCUMENT ME!
     * @param certificateprofileid DOCUMENT ME!
     * @param timecreated DOCUMENT ME!
     * @param timemodified DOCUMENT ME!
     * @param tokentype Type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc
     * @param hardtokenissuerid DOCUMENT ME!

     */
    public EndEntityInformation(String user, String dn, int caid, String subjectaltname, String email, int status, int type, int endentityprofileid, int certificateprofileid,
                         Date timecreated, Date timemodified, int tokentype, int hardtokenissuerid, ExtendedInformation extendedinfo) {
        setUsername(user);
        setPassword(null);
        setCardNumber(null);
        setDN(dn);
        setCAId(caid);
        setSubjectAltName(subjectaltname);
        setEmail(email);
        setStatus(status);
        setType(type);
        setEndEntityProfileId(endentityprofileid);
        setCertificateProfileId(certificateprofileid);
        setTimeCreated(timecreated);
        setTimeModified(timemodified);
        setTokenType(tokentype);
        setHardTokenIssuerId(hardtokenissuerid);
        setExtendedinformation(extendedinfo);
        setCardNumber(null);
    }
    
    /**
     * Creates new EndEntityInformation. This constructor should only be used from UserDataSource 
     * implementations. Status and dates aren't used in these cases.
     * 
     * @param user 
     * @param dn 
     * @param caid CA id of the CA that the user is registered with
     * @param subjectaltname 
     * @param email 
     * @param type one of EndEntityConstants.USER_ENDUSER || ...
     * @param endentityprofileid 
     * @param certificateprofileid 
     * @param tokentype 
     * @param hardtokenissuerid 
     * @param extendedinfo
     */
    public EndEntityInformation(String user, String dn, int caid, String subjectaltname, String email,  int type, int endentityprofileid, int certificateprofileid,
                          int tokentype, int hardtokenissuerid, ExtendedInformation extendedinfo) {
        setUsername(user);
        setPassword(null);
        setDN(dn);
        setCAId(caid);
        setSubjectAltName(subjectaltname);
        setEmail(email);        
        setType(type);
        setEndEntityProfileId(endentityprofileid);
        setCertificateProfileId(certificateprofileid);
        setTokenType(tokentype);
        setHardTokenIssuerId(hardtokenissuerid);
        setExtendedinformation(extendedinfo);
        setCardNumber(null);
    }
    
    
    public void setUsername(String user) { this.username=StringTools.putBase64String(StringTools.strip(user));}
    public String getUsername() {return StringTools.getBase64String(username);}
    public void setDN(String dn) {
    	final StringBuilder removedAllEmpties = new StringBuilder(dn.length());
    	final StringBuilder removedTrailingEmpties = DNFieldsUtil.removeEmpties(dn, removedAllEmpties, true);
    	if (removedTrailingEmpties == null) {
        	this.subjectDNClean=StringTools.putBase64String(removedAllEmpties.toString());
        	this.subjectDN=this.subjectDNClean;
    	} else {
        	this.subjectDNClean=StringTools.putBase64String(removedAllEmpties.toString());
        	this.subjectDN=StringTools.putBase64String(removedTrailingEmpties.toString());
    	}
    }
    
    /** User DN as stored in the database. If the registered DN has unused DN fields the empty ones are kept, i.e.
     * CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an explanation of this.
     * Use method getCertificateDN() to get the DN stripped from empty fields.
     * @see #getCertificateDN()
     * @return String with DN, might contain empty fields, use getCertificateDN to get without empty fields
     */
    public String getDN() {return StringTools.getBase64String(subjectDN);}
    public int getCAId(){return this.caid;}
    public void setCAId(int caid){this.caid=caid;}
    public void setSubjectAltName( String subjectaltname) { this.subjectAltName=StringTools.putBase64String(subjectaltname); }
    public String getSubjectAltName() {return StringTools.getBase64String(subjectAltName);}
    public void setEmail(String email) {this.subjectEmail = StringTools.putBase64String(email);}
    public String getEmail() {return StringTools.getBase64String(subjectEmail);}
    public void setCardNumber(String cardNumber) {this.cardNumber =  StringTools.putBase64String(cardNumber);}
    public String getCardNumber() {return StringTools.getBase64String(cardNumber);}
    public void setPassword(String pwd) {this.password = StringTools.putBase64String(pwd);}
    public String getPassword() {return StringTools.getBase64String(password);}
    public void setStatus(int status) {this.status=status;}
    public int getStatus() {return status;}
    public void setType(int type) {this.type=type;}
    public int getType() {return type;}
    public void setEndEntityProfileId(int endentityprofileid) { this.endentityprofileid=endentityprofileid; }
    public int getEndEntityProfileId(){ return this.endentityprofileid; }
    public void setCertificateProfileId(int certificateprofileid) { this.certificateprofileid=certificateprofileid; }
    public int getCertificateProfileId() {return this.certificateprofileid;}
    public void setTimeCreated(Date timecreated) { this.timecreated=timecreated; }
    public Date getTimeCreated() {return this.timecreated;}
    public void setTimeModified(Date timemodified) { this.timemodified=timemodified; }
    public Date getTimeModified() {return this.timemodified;}
    public int getTokenType(){ return this.tokentype;}
    public void setTokenType(int tokentype) {this.tokentype=tokentype;}
    public int getHardTokenIssuerId() {return this.hardtokenissuerid;}
    public void setHardTokenIssuerId(int hardtokenissuerid) { this.hardtokenissuerid=hardtokenissuerid;}

    /**
     * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This method is still used for deserializing objects in CertReqHistoryDataBean. 
     */
    public boolean getAdministrator(){
      return (type & SecConst.USER_ADMINISTRATOR) == SecConst.USER_ADMINISTRATOR;
    }

    /**
     * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This method is still used for deserializing objects in CertReqHistoryDataBean. 
     */
    public void setAdministrator(boolean administrator){
      if(administrator) {
        type = type | SecConst.USER_ADMINISTRATOR;
      } else {
        type = type & (~SecConst.USER_ADMINISTRATOR);
      }
    }

    public boolean getKeyRecoverable(){
      return (type & SecConst.USER_KEYRECOVERABLE) == SecConst.USER_KEYRECOVERABLE;
    }

    public void setKeyRecoverable(boolean keyrecoverable){
      if(keyrecoverable) {
        type = type | SecConst.USER_KEYRECOVERABLE;
      } else {
        type = type & (~SecConst.USER_KEYRECOVERABLE);
      }
    }

    public boolean getSendNotification(){
      return (type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION;
    }

    
    public void setSendNotification(boolean sendnotification){
      if(sendnotification) {
        type = type | SecConst.USER_SENDNOTIFICATION;
      } else {
        type = type & (~SecConst.USER_SENDNOTIFICATION);
      }
    }
    
    public boolean getPrintUserData(){
        return (type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION;
      }

    public void setPrintUserData(boolean printUserData){
        if(printUserData) {
          type = type | SecConst.USER_PRINT;
        } else {
          type = type & (~SecConst.USER_PRINT);
        }
   }

	/**
	 * @return Returns the extendedinformation or null if no extended information exists.
	 */
	public ExtendedInformation getExtendedinformation() {
		return extendedinformation;
	}
	/**
	 * @param extendedinformation The extendedinformation to set.
	 */
	public void setExtendedinformation(ExtendedInformation extendedinformation) {
		this.extendedinformation = extendedinformation;
	}
	
	
    /**
     * Help Method used to create an ExtendedInformation from String representation.
     * Used when creating an ExtendedInformation from queries.
     */
    public static ExtendedInformation getExtendedInformation(String extendedinfostring) {
        ExtendedInformation returnval = null;
        if ( (extendedinfostring != null) && (extendedinfostring.length() > 0) ) {
            try {
            	java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(extendedinfostring.getBytes("UTF8")));            	
            	HashMap h = (HashMap) decoder.readObject();
            	decoder.close();
                // Handle Base64 encoded string values
                HashMap data = new Base64GetHashMap(h);
                // type = ExtendedInformation.TYPE
            	int type = ((Integer) data.get("type")).intValue();
            	switch(type){
            	  case 0: //ExtendedInformation.TYPE_BASIC
              		returnval = new ExtendedInformation();            	
              		returnval.loadData(data);
              		break;
            	}            	
            }catch (Exception e) {
            	throw new RuntimeException("Problems generating extended information from String",e);
            }
        }
        return returnval;
    }
    
    public static String extendedInformationToStringData(ExtendedInformation extendedinformation) throws UnsupportedEncodingException {
    	String ret = null;
    	if(extendedinformation != null){
            // We must base64 encode string for UTF safety
            HashMap a = new Base64PutHashMap();
            a.putAll((HashMap)extendedinformation.saveData());
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    		encoder.writeObject(a);
    		encoder.close();
    		ret = baos.toString("UTF8");
    	}
    	return ret;
    }

    /** @return the DN to be used when creating a certificate (without empty fields).
     * If the registered DN has unused DN fields the empty ones are kept, i.e.
     * CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an explanation of this.
     * Use method getCertificateDN() to get the DN stripped from empty fields, getDN() returns DN with empty fields.
     * @see #getDN()
     * @return String with DN, with no empty fields, use getDN to get including empty fields
     */
    public String getCertificateDN() {
    	if (subjectDNClean == null) {
    		// This might be fetched from database serialization so we need to perform the cleaning all over again
    		return DNFieldsUtil.removeAllEmpties(getDN());
    	} else {
            return StringTools.getBase64String(subjectDNClean);
    	}
    }
}
