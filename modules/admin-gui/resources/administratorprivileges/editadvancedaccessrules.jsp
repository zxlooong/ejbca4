<%
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
 
 // Original version by Philip Vendil.
 
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration" %>
 
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
 
<% 
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/system_functionality/edit_administrator_privileges"); 
%>
 
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script language="javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>
 
<div align="center">

	<h2><h:outputText value="#{web.text.EDITACCESSRULES}" /></h2>
	<h3><h:outputText value="#{web.text.ADMINGROUP} : #{adminGroupsManagedBean.currentAdminGroup}" /></h3>

	<h:outputText value="#{web.text.AUTHORIZATIONDENIED}" rendered="#{!adminGroupsManagedBean.authorizedToGroup}"/>

</div>


	<h:panelGroup rendered="#{adminGroupsManagedBean.authorizedToGroup}">
	<h:messages layout="table" errorClass="alert"/>

	<h:panelGrid styleClass="edit-top" width="100%" columns="1" rowClasses="Row0,Row1" style="text-align: right;">
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/administratorprivileges.jsf"
			title="#{web.text.BACKTOADMINGROUPS}">
			<h:outputText value="#{web.text.BACKTOADMINGROUPS}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadminentities.jsf?currentAdminGroup=#{adminGroupsManagedBean.currentAdminGroup}"
			title="#{web.text.EDITADMINS}" rendered="#{not empty adminGroupsManagedBean.currentAdminGroup}">
			<h:outputText value="#{web.text.EDITADMINS}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentAdminGroup=#{adminGroupsManagedBean.currentAdminGroup}"
			rendered="#{not empty adminGroupsManagedBean.currentAdminGroup && !adminGroupsManagedBean.basicRuleSet.forceAdvanced}"
			title="#{web.text.BASICMODE}">
			<h:outputText value="#{web.text.BASICMODE}"/>
		</h:outputLink>
	</h:panelGrid>
	
	<h:form id="accessRulesForm" rendered="#{not empty adminGroupsManagedBean.currentAdminGroup}">
	<h:inputHidden id="currentAdminGroup" value="#{adminGroupsManagedBean.currentAdminGroup}" />
	<h:dataTable value="#{adminGroupsManagedBean.accessRulesCollections}" var="accessRuleCollection"
		headerClass="listHeader" style="width: 100%;">
		<h:column>
		<h:dataTable value="#{accessRuleCollection.collection}" var="accessRule" rendered="#{not empty accessRuleCollection.collection}"
			headerClass="listHeader" rowClasses="Row0,Row1" columnClasses="rulesColumn1,rulesColumn2,rulesColumn2" style="width: 100%">
			<f:facet name="header">
				<h:outputText value="#{web.text[accessRuleCollection.name]}"/>
			</f:facet>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RESOURCE}" />
				</f:facet>
				<h:outputText value="#{adminGroupsManagedBean.parsedAccessRule}"/>
			</h:column>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RULE}" />
				</f:facet>
				<h:selectOneMenu id="selectrole" value="#{accessRule.rule}">
					<f:selectItems value="#{adminGroupsManagedBean.accessRuleRules}" />
				</h:selectOneMenu> 
			</h:column>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RECURSIVE}" />
				</f:facet>
				<h:selectBooleanCheckbox value="#{accessRule.recursive}" />
			</h:column>
		</h:dataTable>
		</h:column>
	</h:dataTable>

	<h:panelGrid styleClass="edit-bottom" width="100%" columns="1" style="text-align: center;">
		<h:panelGroup>
			<h:commandButton action="#{adminGroupsManagedBean.saveAdvancedAccessRules}" value="#{web.text.SAVE}"/>
			<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
			<h:commandButton action="#{adminGroupsManagedBean.restoreAdvancedAccessRules}" value="#{web.text.RESTORE}"/>
		</h:panelGroup>
	</h:panelGrid>

	</h:form>

	</h:panelGroup>


<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
