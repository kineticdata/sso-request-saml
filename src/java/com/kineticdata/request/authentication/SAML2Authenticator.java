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
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SingleSignOnServiceElement;
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
    private static final String ARS_USER_FORM_DISABLED_STATUS_VALUE = "Disabled";
    private static final String AUTHENTICATION_URL = "/login.jsp";
    private static final String AUTHENTICATION_SAML_ATTRIBUTE = "uid";
    private static final String SOURCE_FORM = "User";
    private static final String SOURCE_LOOKUPFIELD = "Login Name";
    private static final String SOURCE_RETURNFIELD = "101";
    
    private final String LOGGER_ID = getClass().getSimpleName() + " :: ";

    // Instance variables
    private String arsUserFormDisabledStatusValue;
    private String enableLogging;
    private String compareNameIdOrAttribute;
    private String samlAttributeKey;
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
        
        samlAttributeKey = properties.getProperty("SAML2Authenticator.attributeKey");
        if (samlAttributeKey == null || samlAttributeKey.trim().length()==0) {
            samlAttributeKey = AUTHENTICATION_SAML_ATTRIBUTE;
        }
        
        compareNameIdOrAttribute = properties.getProperty("SAML2Authenticator.nameId.or.attribute");
        if (compareNameIdOrAttribute == null || compareNameIdOrAttribute.trim().length()==0) {
            compareNameIdOrAttribute = "nameid";
        }

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
        
        // The Remedy User form status value indicating the Remedy User account is disabled
        arsUserFormDisabledStatusValue = properties.getProperty("ARS.UserForm.DisabledStatusValue");
        if (arsUserFormDisabledStatusValue == null || arsUserFormDisabledStatusValue.trim().length()==0) {
            arsUserFormDisabledStatusValue = ARS_USER_FORM_DISABLED_STATUS_VALUE;
        }

        routeLogoutUrl = properties.getProperty("SAML2Authenticator.route.logoutURL");
        
        if (isLoggingEnabled) {
            logger.info(LOGGER_ID + 
                "fedlet home directory: " + getFedletHome());
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
                logger.debug(LOGGER_ID
                        +"User is already authenticated: "+localUserContext.getUserName());
            }
            authorized = true;
        } else {
            String loginId = null;

            if (getRequest().getParameter("SAMLResponse") != null) {
                
                // BEGIN : following code is a must for Fedlet (SP) side applications
                Map map;
                try {
                    // invoke the Fedlet processing logic. this will do all the
                    // necessary processing conforming to SAMLv2 specifications,
                    // such as XML signature validation, Audience and Recipient
                    // validation etc.
                    map = SPACSUtils.processResponseForFedlet(getRequest(), getResponse(), getResponse().getWriter());
                } catch (SAML2Exception sme) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR, "failedToProcessSSOResponse",
                        sme.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(LOGGER_ID +
                            "SAML2 Response parsing exception: " + sme.getMessage());
                    }
                    return false;
                } catch (IOException ioe) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR, "failedToProcessSSOResponse",
                        ioe.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(LOGGER_ID +
                            "IO Exception: " + ioe.getMessage());
                    }
                    return false;
                } catch (SessionException se) {
                    SAMLUtils.sendError(getRequest(), 
                        getResponse(),
                        getResponse().SC_INTERNAL_SERVER_ERROR,
                        "failedToProcessSSOResponse",
                        se.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(LOGGER_ID +
                            "Session Exception: " + se.getMessage());
                    }
                    return false;
                } catch (ServletException se) {
                    SAMLUtils.sendError(getRequest(), getResponse(),
                        getResponse().SC_BAD_REQUEST, "failedToProcessSSOResponse",
                        se.getMessage());
                    if (isLoggingEnabled) {
                        logger.error(LOGGER_ID +
                            "Servlet Exception: " + se.getMessage());
                    }
                    return false;
                } finally {
                    if (isLoggingEnabled && logger.isTraceEnabled()) {
                        logger.trace(LOGGER_ID +
                            "SAMLResponse: " + getRequest().getParameter("SAMLResponse"));
                    }
                }
                // END : code is a must for Fedlet (SP) side application
                
                String samlUser = getUsernameFromSamlResponse(map);
                
                if (samlUser != null) {
                    // If the Remedy Login Name should be translated from Remedy
                    if (this.lookupFromARS) {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(LOGGER_ID
                                    +"Lookup Remedy Login Name from Remedy form "+this.sourceForm);
                        }
                        loginId = getRemedyLoginId(samlUser);
                    }
                    // Else just use the user name extracted from the SAML Assertion.
                    else {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(LOGGER_ID
                                    +"Submitting Remedy Login Name directly from the SAML response - " + samlUser);
                        }
                        loginId = samlUser;
                    }

                    // If the Remedy Login Name has been determined, authenticate the user
                    if (loginId != null && loginId.length() > 0) {
                        
                        // If the Remedy User account is NOT disabled
                        if (!isUserAccountDisabled(loginId)) {
                        
                            if (isLoggingEnabled && logger.isDebugEnabled()) {
                                logger.debug(LOGGER_ID +"Authenticating user: "+loginId);
                            }
                            authenticate(loginId, null, null);
                            if (isLoggingEnabled && logger.isDebugEnabled()) {
                                logger.debug(LOGGER_ID +"Authenticated user: "+loginId);
                            }

                            if (isLoggingEnabled && logger.isDebugEnabled()) {
                                logger.debug(LOGGER_ID
                                        +"Redirecting user to destination url: " + localUserContext.getFullRedirectURL());
                            }
                            doRedirect(localUserContext.getFullRedirectURL());
                            
                        // If the Remedy User account IS disabled...
                        } else {
                            
                        }
                    }
                    // Remedy Login Name is null or blank
                    else {
                        if (isLoggingEnabled && logger.isDebugEnabled()) {
                            logger.debug(LOGGER_ID +"Remedy Login Name was blank");
                        }
                        // Send to authentication URL
                        sendToAuthenticationUrl();
                    }
                } else {
                    logger.debug(LOGGER_ID + 
                            "Could not find a username in the SAML Response. Check to see if the nameid.or.attribute property is setup correctly. Login failed.");                    
                }

            // No SAMLResponse Request Parameter found...Do redirect to IdP.
            } else {

                // TODO?: Take config params that specify SP & IdP info
                SAML2MetaManager manager = new SAML2MetaManager();
                List idpEntities = manager.getAllRemoteIdentityProviderEntities("/");
                List spEntities = manager.getAllHostedServiceProviderEntities("/");
                String spEntityID = (String) spEntities.get(0);
                List spMetaAliases = manager.getAllHostedServiceProviderMetaAliases("/");
                String idpEntityID = (String) idpEntities.get(0);
                String metaAlias = (String) spMetaAliases.get(0);
                Map paramsMap = SAML2Utils.getParamsMap(getRequest());
                
                SPSSODescriptorElement spDescriptor = manager.getSPSSODescriptor("/", spEntityID);
                IDPSSODescriptorElement idpDescriptor = manager.getIDPSSODescriptor("/", idpEntityID);
                SingleSignOnServiceElement idpFirstSingleSignonEndpoint = 
                        (SingleSignOnServiceElement)idpDescriptor.
                        getSingleSignOnService().
                        get(0);
                
                ArrayList idpBindingList = new ArrayList();
                idpBindingList.add(idpFirstSingleSignonEndpoint.getBinding());
                
                paramsMap.put(SAML2Constants.NAMEID_POLICY_FORMAT, idpDescriptor.getNameIDFormat());
                paramsMap.put(SAML2Constants.REQ_BINDING, idpBindingList);

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
                logger.error(LOGGER_ID +message);
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
                logger.debug(LOGGER_ID +"logging out user and redirecting to: "
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
    
    private String getUsernameFromSamlResponse(Map map) throws SAML2Exception {
        String result = null;
        
        Response samlResp = (Response) map.get(SAML2Constants.RESPONSE); 
        Assertion assertion = (Assertion) map.get(SAML2Constants.ASSERTION);
        Subject subject = (Subject) map.get(SAML2Constants.SUBJECT);
        String entityID = (String) map.get(SAML2Constants.IDPENTITYID);
        String spEntityID = (String) map.get(SAML2Constants.SPENTITYID);
        String sessionIndex = (String) map.get(SAML2Constants.SESSION_INDEX);
        Map attrs = (Map)map.get(SAML2Constants.ATTRIBUTE_MAP);
        NameID nameId = (NameID) map.get(SAML2Constants.NAMEID);
        
        // Heavy duty logging for troubleshooting in the future.
        if (isLoggingEnabled && logger.isTraceEnabled()) {

            logger.trace(LOGGER_ID + "IDP Entity ID: " + entityID);

            if (nameId.getFormat() != null) {
                logger.trace(LOGGER_ID +
                    "NameID format: " + nameId.getFormat());
            }
            if (nameId.getValue() != null) {
                logger.trace(LOGGER_ID +
                    "NameID value: " + nameId.getValue());
            }
            if (sessionIndex != null) {
                logger.trace(LOGGER_ID +
                    "SessionIndex: " + sessionIndex);
            }
            if (samlResp != null) {
                logger.trace(LOGGER_ID +
                    "SAML Response: " + samlResp.toXMLString());
            }
            if (subject != null) {
                logger.trace(LOGGER_ID +
                    "SAML Subject: " + subject);
            }
            if (assertion != null) {
                logger.trace(LOGGER_ID +
                    "SAML Assertion: " + assertion.toXMLString());
            }
        }
            
        if (attrs != null) {
            logger.debug(LOGGER_ID + "SAML Attribute Map size: " + String.valueOf(attrs.size()));
            if (attrs.isEmpty()) { 
                logger.debug(LOGGER_ID + "Make sure mapped attributes in sp-extended.xml are set properly.");
            } else {
                Iterator iter = attrs.keySet().iterator();
                while (iter.hasNext()) {
                    String attrName = (String) iter.next();
                    Set attrVals = (HashSet) attrs.get(attrName);
                    if ((attrVals != null) && !attrVals.isEmpty()) {
                        Iterator it = attrVals.iterator();
                        while (it.hasNext()) {
                            logger.debug(LOGGER_ID + "ATTRIBUTE: " + attrName + "=" + it.next());
                        }
                    }
                }
                getRequest().
                    getSession(true).
                    setAttribute(
                        "SAML Assertion Attributes",
                        attrs
                    );
            }
        } else {
            logger.debug(LOGGER_ID + "ATTRIBUTE_MAP returned null");
        }

        if (this.compareNameIdOrAttribute.trim().toLowerCase().equals("nameid")) {
            result = nameId.getValue();
        } else {
            Set sUser = (HashSet)attrs.get(samlAttributeKey);
            if (sUser != null) {
                result = (String)sUser.iterator().next();
            } else {
                logger.debug(LOGGER_ID + samlAttributeKey + " attribute not found in SAML Response assertion attributes. Double check sp-extended.xml is properly configured for attribute mappings.");
            }
        }
        
        return result;
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
                    logger.debug(LOGGER_ID + "Remedy query: " + qualification);
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
                    logger.error(LOGGER_ID +"Error retriving user record from Remedy", e);
                }
            }
        }
        return userId;
    }
    
    /**
     * Checks if the Remedy User account is disabled for the provided login id.
     *
     * <p>This method explictly check for Disabled instead of "Current" for the possibility
     * of allowing guest users.  This would only be achieved if the LookupARS configuration
     * property value was set to False (F).</p>
     *
     * <p>If the user record is not found, this method returns false, indicating the user account
     * is NOT disabled, because technically it isn't.</p>
     * 
     * @param remedyLoginId The Remedy Login ID that will be checked.
     * @return true if the User record is disabled, else false
     */
    private boolean isUserAccountDisabled(String remedyLoginId) {
        // Declare the result
        boolean disabled = false;

        // Field IDs on the Remedy User form
        String STATUS_FIELD_ID = "7";
        String REMEDY_LOGIN_FIELD_ID = "101";
        // Define the fields to return with the entry
        String[] fields = {STATUS_FIELD_ID};
        // Look up the Remedy User record if a login was provided
        if (remedyLoginId != null && remedyLoginId.length() > 0) {
            try {
                // Use ArsHelpers to avoid calling the Remedy API directly
                ArsPrecisionHelper helper = new ArsPrecisionHelper(RemedyHandler.getDefaultHelperContext());
                SimpleEntry entry = helper.getFirstSimpleEntry("User", "'"+REMEDY_LOGIN_FIELD_ID+"'=\""+remedyLoginId+"\"", fields);
                // If the entry was found
                if (entry != null) {
                    String status = entry.getEntryFieldValue(STATUS_FIELD_ID);
                    disabled = arsUserFormDisabledStatusValue.equals(status);
                    if (logger.isTraceEnabled()) {
                        logger.trace(LOGGER_ID +"The status of the Remedy User account for "+remedyLoginId+" is "+status);
                    }
                }
                // Entry was not found
                else {
                    if (logger.isTraceEnabled()) {
                        logger.trace(LOGGER_ID +"Failed to retreived the Remedy User account for loginId: "+remedyLoginId);
                    }
                }
            }
            catch (Exception e) {
                if (logger.isTraceEnabled()) {
                    logger.trace(LOGGER_ID +"Failed to retreived Remedy User account for loginId: "+remedyLoginId, e);
                }
            }
        }
        return disabled;
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
                logger.debug(LOGGER_ID
                        +"Sending to Authentication URL for direct ARS authentication: "
                        +fullRedirectURL);
            }
            doRedirect(fullRedirectURL);
        }
    }

}
