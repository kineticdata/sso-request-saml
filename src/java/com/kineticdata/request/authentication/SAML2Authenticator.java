package com.kineticdata.request.authentication;

import com.kd.arsHelpers.ArsPrecisionHelper;
import com.kd.arsHelpers.SimpleEntry;
import com.kd.kineticSurvey.authentication.Authenticator;
import static com.kd.kineticSurvey.authentication.Authenticator.logger;
import com.kd.kineticSurvey.beans.UserContext;
import com.kd.kineticSurvey.impl.RemedyHandler;

import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.saml.common.SAMLUtils;
import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.assertion.Subject;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.profile.SPACSUtils;
import com.sun.identity.saml2.profile.SPSSOFederate;
import com.sun.identity.saml2.protocol.Response;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.servlet.ServletException;


/**
 * This is a SAML2 authenticator for Kinetic Request using OpenAM Fedlet.
 * A circle of trust must be established between Kinetic Request (Service Provider) and
 * an Identity Provider. This is done by providing the Identity Provider the SAML SSO
 * metadata information (sp.xml) and the the Identity Providers metadata (id.xml) put 
 * into the fedlet config directory path. The fedlet config directory path is 
 * %home%/fedlet if java parameter -Dcom.sun.identity.fedlet.home is not defined.
 * 
 */
public class SAML2Authenticator extends Authenticator {
    // Constants
    // These values represent defaults, but can be overridden in the properties file
    private static final String SOURCE_FORM = "User";
    private static final String SOURCE_LOOKUPFIELD = "Login Name";
    private static final String SOURCE_RETURNFIELD = "101";
    private static final String AUTHENTICATION_URL = "/login.jsp";

    // Instance variables
    private String enableLogging;
    private String lookupArs;
    private String sourceForm;
    private String sourceLookupField;
    private String sourceReturnField;
    private String routeLogoutUrl;
    private String routeAuthenticationUrl;
    private boolean isLoggingEnabled = true;
    private boolean lookupFromARS = true;

    /*--------------------------------------------------------------------------------------------
     * CONSTRUCTOR
     --------------------------------------------------------------------------------------------*/
    
    /**
     * Set up the properties from the configuration file
     */
    public SAML2Authenticator() {
        Properties properties = getProperties();

        // Debug logging
        enableLogging = properties.getProperty("SAML2Authenticator.enableLogging");
        if ("F".equalsIgnoreCase(enableLogging)) { isLoggingEnabled = false; }

        // Remedy Lookup
        lookupArs = properties.getProperty("SAML2Authenticator.lookupARS");
        if ("F".equalsIgnoreCase(lookupArs)) { lookupFromARS = false; }
        
        sourceForm = properties.getProperty("SAML2Authenticator.source.form");
        if (sourceForm == null || sourceForm.trim().length()==0) { sourceForm = SOURCE_FORM; }
        
        sourceLookupField = properties.getProperty("SAML2Authenticator.source.lookupField");
        if (sourceLookupField == null || sourceLookupField.trim().length()==0) { sourceLookupField = SOURCE_LOOKUPFIELD; }
        
        sourceReturnField = properties.getProperty("SAML2Authenticator.source.returnField");
        if (sourceReturnField == null || sourceReturnField.trim().length()==0) { sourceReturnField = SOURCE_RETURNFIELD; }

        // Routes
        routeAuthenticationUrl = properties.getProperty("SAML2Authenticator.route.authenticationURL");
        if (routeAuthenticationUrl == null || routeAuthenticationUrl.trim().length()==0) {
            routeAuthenticationUrl = AUTHENTICATION_URL;
        }

        routeLogoutUrl = properties.getProperty("SAML2Authenticator.route.logoutURL");
        
        if (isLoggingEnabled) {
            logger.info(getClass().getSimpleName()+ 
                " - fedlet home directory: " + getFedletHome());
        }
    }
    
    
    /*--------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     --------------------------------------------------------------------------------------------*/
    
    /**
     * This method checks if the user is authenticated, and if not, redirects the user
     * to the authentication url.
     *
     * Called from the authentication servlet.
     *
     * @return true if user is authenticated, else false
     * @throws Exception
     */
    @Override
    public boolean authorizeSession() throws Exception {
        UserContext localUserContext = getUserContext();
        boolean authorized = false;
        if (localUserContext.isAuthenticated()) {
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()
                        +" - User is already authenticated: "+localUserContext.getUserName());
            }
            authorized = true;
        } else {
            String loginId = null;

            if (getRequest().getParameter("SAMLResponse") != null) {
                
                // BEGIN : following code is a must for Fedlet (SP) side application
                Map map;
                try {
                    // invoke the Fedlet processing logic. this will do all the
                    // necessary processing conforming to SAMLv2 specifications,
                    // such as XML signature validation, Audience and Recipient
                    // validation etc.
                    map = SPACSUtils.processResponseForFedlet(getRequest(), getResponse());
                } catch (SAML2Exception sme) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR, "failedToProcessSSOResponse",
                        sme.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(this.getClass().getSimpleName()+
                            " - SAML2 Response parsing exception: " + sme.getMessage());
                    }
                    return false;
                } catch (IOException ioe) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR, "failedToProcessSSOResponse",
                        ioe.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(this.getClass().getSimpleName()+
                            " - IO Exception: " + ioe.getMessage());
                    }
                    return false;
                } catch (SessionException se) {
                    SAMLUtils.sendError(getRequest(), 
                        getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR,
                        "failedToProcessSSOResponse",
                        se.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(this.getClass().getSimpleName()+
                            " - Session Exception: " + se.getMessage());
                    }
                    return false;
                } catch (ServletException se) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_BAD_REQUEST, "failedToProcessSSOResponse",
                        se.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(this.getClass().getSimpleName()+
                            " - Servlet Exception: " + se.getMessage());
                    }
                    return false;
                } finally {
                    if (isLoggingEnabled && logger.isTraceEnabled()) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SAMLResponse: " + getRequest().getParameter("SAMLResponse"));
                    }
                }
                // END : code is a must for Fedlet (SP) side application
                
                // Heavy duty logging for troubleshooting in the future.
                if (isLoggingEnabled && logger.isTraceEnabled()) {
                    Response samlResp = (Response) map.get(SAML2Constants.RESPONSE); 
                    Assertion assertion = (Assertion) map.get(SAML2Constants.ASSERTION);
                    Subject subject = (Subject) map.get(SAML2Constants.SUBJECT);
                    String entityID = (String) map.get(SAML2Constants.IDPENTITYID);
                    String spEntityID = (String) map.get(SAML2Constants.SPENTITYID);
                    String sessionIndex = (String) map.get(SAML2Constants.SESSION_INDEX);
                    NameID nameId = (NameID) map.get(SAML2Constants.NAMEID);
                    String value = nameId.getValue();
                    String format = nameId.getFormat();

                    if (logger.isTraceEnabled()) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - IDP Entity ID: " + entityID);
                    }
                    
                    if (format != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - NameID format: " + format);
                    }
                    if (value != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - NameID value: " + value);
                    }
                    if (sessionIndex != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SessionIndex: " + sessionIndex);
                    }
                    if (samlResp != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SAML Response: " + samlResp.toXMLString());
                    }
                    if (subject != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SAML Subject: " + subject);
                    }
                    if (assertion != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SAML Assertion: " + assertion.toXMLString());
                    }
                    if (assertion != null) {
                        logger.trace(this.getClass().getSimpleName()+
                            " - SAML Assertion: " + assertion.toXMLString());
                    }
                }
                
                Map attrs = (Map)map.get(SAML2Constants.ATTRIBUTE_MAP);
                
                if (isLoggingEnabled && logger.isDebugEnabled()) {
                    if (attrs != null) {
                        logger.debug(this.getClass().getSimpleName()+ " - SAML Attribute Map size: " + String.valueOf(attrs.size()));
                        if (attrs.isEmpty()) { 
                            logger.debug(this.getClass().getSimpleName()+ " - Make sure mapped attributes in sp-extended.xml are set properly.");
                        }
                        Iterator iter = attrs.keySet().iterator();
                        while (iter.hasNext()) {
                            String attrName = (String) iter.next();
                            Set attrVals = (HashSet) attrs.get(attrName);
                            if ((attrVals != null) && !attrVals.isEmpty()) {
                                Iterator it = attrVals.iterator();
                                while (it.hasNext()) {
                                    logger.debug(this.getClass().getSimpleName()+ "ATTRIBUTE: " + attrName + "=" + it.next());
                                }
                            }
                        }
                    } else {
                        logger.debug(this.getClass().getSimpleName()+" - ATTRIBUTE_MAP returned null");
                    }
                }
                
                
                Set sUser = (HashSet)attrs.get("uid");
                if (sUser != null) {
                    String[] samlUser = (String[])sUser.toArray(new String[0]);
                
                    // If the Remedy Login Name should be translated from Remedy
                    if (this.lookupFromARS) {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()
                                    +" - Lookup Remedy Login Name from Remedy form "+this.sourceForm);
                        }
                        loginId = getRemedyLoginId(samlUser[0]);
                    }
                    // Else just use the user name extracted from the SAML Assertion.
                    else {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()
                                    +" - Submitting Remedy Login Name directly from the first mapped SAML attribute uid.");
                        }
                        loginId = samlUser[0];
                    }

                    // If the Remedy Login Name has been determined, authenticate the user
                    if (loginId != null && loginId.length() > 0) {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Authenticating user: "+loginId);
                        }
                        authenticate(loginId, null, null);
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Authenticated user: "+loginId);
                        }

                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()
                                    +" - Redirecting user to destination url: " + localUserContext.getFullRedirectURL());
                        }
                        doRedirect(localUserContext.getFullRedirectURL());
                    }
                    // Remedy Login Name is null or blank
                    else {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(this.getClass().getSimpleName()+" - Remedy Login Name was blank");
                        }
                        // Send to authentication URL
                        sendToAuthenticationUrl();
                    }
                } else {
                    logger.debug("Could not find uid mapped attribute. Login failed.");                    
                }

            // No SAMLResponse Request Parameter found...Do redirect to IdP.
            } else {

                // TODO: Take config params that specify SP & IdP info?
                SAML2MetaManager manager = new SAML2MetaManager();
                List idpEntities = manager.getAllRemoteIdentityProviderEntities("/");
                List spMetaAliases = manager.getAllHostedServiceProviderMetaAliases("/");
                String idpEntityID = (String) idpEntities.get(0);
                String metaAlias = (String) spMetaAliases.get(0);
                Map paramsMap = SAML2Utils.getParamsMap(getRequest());

                List list = new ArrayList();
                list.add(SAML2Constants.NAMEID_TRANSIENT_FORMAT);
                paramsMap.put(SAML2Constants.NAMEID_POLICY_FORMAT, list);

                if (paramsMap.get(SAML2Constants.BINDING) == null) {
                    // use POST binding for default
                    list = new ArrayList();
                    list.add(SAML2Constants.HTTP_POST);
                    paramsMap.put(SAML2Constants.BINDING, list);
                }

                try {
                    
                    // Set the redirection properties in the user context
                    String destination = getRequest().getRequestURL() + "?" + getRequest().getQueryString();
                    localUserContext.setInRedirect(true);
                    localUserContext.setFullRedirectURL(destination);
                    // add the authenticated back into the session
                    getRequest().getSession(true).setAttribute("UserContext", localUserContext);
                    
                    SPSSOFederate.initiateAuthnRequest(
                        getRequest(),
                        getResponse(),
                        metaAlias,
                        idpEntityID,
                        paramsMap);
                    
                    // TODO: Find a way to get SAMLRequest built by code above.
                    // It would be valuable to log in a trace.
                    
                } catch (SAML2Exception sse) {
                    SAML2Utils.debug.error("Error sending AuthnRequest " , sse);
                    SAMLUtils.sendError(
                        getRequest(),
                        getResponse(),
                        getResponse().SC_BAD_REQUEST,
                        "requestProcessingError", 
                        SAML2Utils.bundle.getString("requestProcessingError") + " " +
                        sse.getMessage());
                } catch (Exception e) {
                    SAML2Utils.debug.error("Error processing Request ",e);
                    SAMLUtils.sendError(getRequest(),
                        getResponse(),
                        getResponse().SC_BAD_REQUEST,
                        "requestProcessingError",
                        SAML2Utils.bundle.getString("requestProcessingError") + " " +
                        e.getMessage());
                }
            }
        }

        return authorized;
    }

    /**
     * Authenticates the user against the Remedy server.
     *
     * @param userName the Remedy LoginId
     * @param password not used in this implementation
     * @param authentication not used in this implementation
     * @throws Exception
     */
    @Override
    public void authenticate(String userName, String password, String authentication) throws Exception {
        if (userName != null && userName.length() > 0) {
            // initialize the user session
            intializeUserSession(userName);
        }
        else {
            String message = "Cannot authenticate with a blank username";
            if (isLoggingEnabled) {
                logger.error(this.getClass().getSimpleName()+" - "+message);
            }
            throw new RuntimeException(message);
        }
    }

    /**
     * Runs when the user logs out of the system.  Simply redirects to the logout page if it
     * is specified in the properties file, otherwise does nothing.
     *
     * @throws Exception
     */
    @Override
    public void logout() throws Exception {
        // set the logout page if it is defined in the properties file
        if ((this.routeLogoutUrl != null) && (this.routeLogoutUrl.length() > 0)) {
            setLogoutPage(this.routeLogoutUrl);
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()+" - logging out user and redirecting to: "
                        +this.routeLogoutUrl);
            }
            doRedirect(this.routeLogoutUrl);
        }
    }

    /**
     * Runs when a user doesn't have the appropriate permissions to access a specific resource.
     *
     * @param errorMessage The error message returned from the server
     * @throws Exception
     */
    @Override
    public void handleIncorrectPermissions(String errorMessage) throws Exception {
        if (getRequestType().equalsIgnoreCase("XMLHttpRequest")) {
            getResponse().setHeader("X-Error-Message", errorMessage);
            getResponse().sendError(403, errorMessage);
        } else {
            getUserContext().setErrorMessage(errorMessage);
            authorizeSession();
        }
    }
    

    /*--------------------------------------------------------------------------------------------
     * PRIVATE HELPER METHODS
     --------------------------------------------------------------------------------------------*/

    /**
     * Lookup the Fedlet Home directory that will be used by the OpenSSO API.
     * This method is only used for logging purposes when troubleshooting. It
     * is never used for loading the actual sp & idp config files. 
     * 
     * @return Fedlet directory path used to read sp.xml, idp.xml, etc files.
     */    
    private String getFedletHome() {
        String fedletHomeDir = System.getProperty("com.sun.identity.fedlet.home");
        if ((fedletHomeDir == null) || (fedletHomeDir.trim().length() == 0)) {
            if (System.getProperty("user.home").equals(File.separator)) {
                fedletHomeDir = File.separator + "fedlet";
            } else {
                fedletHomeDir = System.getProperty("user.home") +
                    File.separator + "fedlet";
            }
        }
        return fedletHomeDir;
    }
    
    /**
     * Lookup the Remedy Login Name from the specified form and fields.  This could be the User 
     * form, the CTM:People form, or some other form that contains a link between the name held in
     * the certificate, and the Remedy Login Name.
     * 
     * @param principalName The value of the distinguished name retrieved from the certificate
     * @return Remedy Login Name that corresponds to the distinguished name in the certificate
     */
    private String getRemedyLoginId(String principalName) {
        String userId = null;
        if (principalName != null && principalName.trim().length() > 0) {
            try {
                // Set the qualification to lookup the record using the certificate's distinguished name
                String qualification = "'"+this.sourceLookupField+"'=\""+principalName+"\"";
                
                if (isLoggingEnabled) {
                    logger.debug("Remedy query: " + qualification);
                }
                
                // Use ArsHelpers to avoid calling the Remedy API directly
                ArsPrecisionHelper helper = new ArsPrecisionHelper(RemedyHandler.getDefaultHelperContext());
                SimpleEntry entry = helper.getFirstSimpleEntry(this.sourceForm, qualification, null);
                if (entry != null) {
                    userId = entry.getEntryFieldValue(this.sourceReturnField);
                }
            }
            catch (Exception e) {
                if (isLoggingEnabled) {
                    logger.error(this.getClass().getSimpleName()+" - Error retriving user record from Remedy", e);
                }
            }
        }
        return userId;
    }
    
    private void sendToAuthenticationUrl() throws Exception {
        // check if the service item specifies an Authentication URL
        String authenticationUrl = getUserContext().getAuthenticationURL();
        if (authenticationUrl == null || authenticationUrl.trim().length() == 0) {
            // check if the authentication url has been defined in the properties file
            authenticationUrl = this.routeAuthenticationUrl;
        }

        // send to the Authentication URL if it is defined
        if (authenticationUrl != null && authenticationUrl.trim().length() > 0) {
            String fullRedirectURL = getRequest().getContextPath() + authenticationUrl;
            getUserContext().setInRedirect(true);
            getUserContext().setAuthenticationType(Authenticator.AUTH_TYPE_DEFAULT);
            getRequest().getSession(true).setAttribute("UserContext", getUserContext());
            if (isLoggingEnabled && logger.isDebugEnabled()) {
                logger.debug(this.getClass().getSimpleName()
                        +" - Sending to Authentication URL for direct ARS authentication: "
                        +fullRedirectURL);
            }
            doRedirect(fullRedirectURL);
        }
    }

}
