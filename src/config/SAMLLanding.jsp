<jsp:useBean id="UserContext" scope="session" class="com.kd.kineticSurvey.beans.UserContext"/>
<%@page
import="com.kineticdata.request.authentication.SAML2Authenticator
"
%>
<%
	try {
		UserContext.setAuthenticationType("External");
		SAML2Authenticator auth = (SAML2Authenticator)SAML2Authenticator.getAuthenticatorInstance(request, response, UserContext);
		auth.authorizeSession();
	} catch (Exception e) {
		out.println(e.getMessage());
	}
%>