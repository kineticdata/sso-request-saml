<%--
   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
  
   Copyright (c) 2009 Sun Microsystems, Inc. All Rights Reserved.
  
   The contents of this file are subject to the terms
   of the Common Development and Distribution License
   (the License). You may not use this file except in
   compliance with the License.
  
   You can obtain a copy of the License at
   https://opensso.dev.java.net/public/CDDLv1.0.html or
   opensso/legal/CDDLv1.0.txt
   See the License for the specific language governing
   permission and limitations under the License.
  
   When distributing Covered Code, include this CDDL
   Header Notice in each file and include the License file
   at opensso/legal/CDDLv1.0.txt.
   If applicable, add the following below the CDDL Header,
   with the fields enclosed by brackets [] replaced by
   your own identifying information:
   "Portions Copyrighted [year] [name of copyright owner]"
  
   $Id: fedletEncode.jsp,v 1.1 2009/11/12 17:30:30 exu Exp $
--%>

<%@page contentType="text/html; charset=UTF-8" %> 
<html>
<head>
    <title>Fedlet Encode</title>
</head>

<%@page import="com.iplanet.services.util.Crypt,
                java.util.ResourceBundle" %>
<%@page import="com.sun.identity.security.EncodeAction,
                 java.security.AccessController" %>


<body class="DefBdy">
    <div class="SkpMedGry1"></div><div class="MstDiv">
    <table title="" border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
        <td width="99%">
        <div ></div>
        </td>
        <td width="1%"></td>
        </tr>
    </table>
    <table border="0" cellpadding="0" cellspacing="0" width="100%"><tr><td></td></tr></table>
    </div>
    <table border="0" cellpadding="5" cellspacing="0" width="100%"><tr><td></td></tr></table>
    <table border="0" cellpadding="10" cellspacing="0" width="100%"><tr><td></td></tr></table>
    <table border="0" cellpadding="10" cellspacing="0" width="100%"><tr><td>

<%
    ResourceBundle rb = null;
    try {
        request.setCharacterEncoding("UTF-8");

        rb = ResourceBundle.getBundle("libSAML2",request.getLocale());
        if (rb == null) {
            rb = ResourceBundle.getBundle("libSAML2");
        }

        String strPwd = request.getParameter("password");

        if ((strPwd != null) && (strPwd.trim().length() > 0))  {
            out.println(rb.getString("result-encoded-pwd") + " ");
            out.println((String) AccessController.doPrivileged(
                new EncodeAction(strPwd.trim())));
            out.println("<br /><br /><a href=\"fedletEncode.jsp\">" +
                rb.getString("encode-another-pwd") + "</a>");
        } else {
            out.println(
            "<form name=\"frm\" action=\"fedletEncode.jsp\" method=\"post\">");
            out.println(rb.getString("prompt-pwd"));
			out.println("<input type=\"password\" name=\"password\" />");
			// add a hidden input element to the HTML form, and set the value to the CSRF token session attribute
			if (session.getAttribute("CsrfToken") != null) {
				out.println("<input type=\"hidden\" id=\"CsrfToken\" name=\"CsrfToken\" value=\"" + session.getAttribute("CsrfToken") + "\"/>");
			}
            out.println("<input type=\"text\" name=\"password\" />");
            out.println("<input type=\"submit\" value=\"" +
                rb.getString("btn-encode") + "\" />");
            out.println("</form>");
        }
    } catch (Exception e) {
        out.println(rb.getString("failed-to-encode"));
    }
%>
</td></tr></table>

</body></html>
