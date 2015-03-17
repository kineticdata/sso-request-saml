# Kinetic Request SAMLv2 Authentication

This project is a Kinetic Request single-sign-on adapter that authenticates users
using OpenAM 12 Fedlet with SAMLv2.

## Change Log

v01.00.00 - 2014-03-10
        - A lot changed. See github commit: https://github.com/kineticdata/sso-request-saml/commit/c09214deb72dd2a33fa92b968a86afca4ad07c76

v00.00.01 - 2013-11-07
        - Initial Implementation


## Development

This application was developed with Netbeans, and includes the Netbeans project files.  Any IDE or 
text editor can be used, but the Ant build script works directly with the Netbeans IDE.


## Build

A Netbeans IDE Ant script is provided that allows Netbeans to build the distribution jar, along
with all the configuration files and required libraries that need to be distributed with the 
project.

Open the project with Netbeans, then build the project.  This will create a `dist` directory in the
main project folder that contains the project jar, along with all the configuration files and 
library files that the application depends upon.

Libraries that are included in this package are for the build only, they are already deployed with 
Kinetic Request:

- `lib/KineticSurveyRequest_V5.jar` (the Kinetic Request application)
- `lib/arapi80_build001.jar` (the Remedy 8.0 API - pure JAVA)
- `lib/kdi_arshelpers.jar` (a helper library for interacting with the Remedy API)
- `lib/log4j-1.2.15.jar` (a logging library)
- `lib/servlet-api.jar` (the servlet 2.4 API specification)


## Deploy

After building the project a `dist` directory will be created to contain all the files that need to
be deployed to the web server.

1.  Copy the `dist/SAMLv2-distribution-package.zip` file to the `<kinetic_request_deploy_directory>` directory,
    and unzip the file choosing to 'extract here' - do not exact to a subdirectory or a new directory.
      
2.  Move ONE of the `fedlet_*` directories now in your `<kinetic_request_deploy_directory>` directory to a 
    non-web-accessible path of your choice. For example:
      Kind-of-good: `c:\fedlet_attriumsso`
	  BAD - DONT DO THIS: `<kinetic_request_deploy_directory>\fedlet_atriumsso`
	  BAD - DONT DO THIS: `<kinetic_request_deploy_directory>\themes\yourtheme\fedlet_atriumsso`
	 
    Document this path.
   
3.  Delete the other `fedlet_*' directories in the `<kinetic_request_deploy_directory>` directory

4.  Add the -Dcom.sun.identity.fedlet.home java parameter to your J2EE server configuration to point to
    the path you chose in step 2. For example: -Dcom.sun.identity.fedlet.home="c:\path\to\step2\fedlet_directory"
   
5.  Configure the fedlet configuration files contained in the directory you chose in step 2.
    See the section below 'Fedlet Configuration' on how to configure these files.
      
6.  Login to the Kinetic Request Admin Console and set the following web application properties:
    - **API Impersonate User** => `true (make sure the checkbox is checked)`
    - **SSO Adapter Class** => `com.kineticdata.request.authentication.SAML2Authenticator`
    - **SSO Adapter Properties** => `c:\path\to\step2\fedlet_directory\samlv2-authenticator.properties`
   
7.  Open the file `c:\path\to\step2\fedlet_directory\FederationConfig.properties`, then do a find & replace for
    ChangeThisValueHere. ChangeThisValueHere should be changed to some string of random characters. This is used
    by the fedletEncode.jsp file to generate encrypted strings.

8.  Restart the J2EE server instance for the new files to be included.

9.  Go to the website: `https://yourkineticrequest.domainhere.com/kinetic/saml2/jsp/fedletEncode.jsp`

10. Choose a keystore/truststore password, DOCUMENT THIS NON-ENCRYPTED PASSWORD SOMEWHERE SAFE, type it into the password box,
    and then hit the button to get an encrypted password.
	
11. Copy the encrypted password text from step 10 and replace the contents of the following files with this encrypted value:
    `c:\path\to\step2\fedlet_directory\storepass.txt`
	`c:\path\to\step2\fedlet_directory\keypass.txt`
   
12. Setup a keystore.jks file in the directory from step 2 and import any IDP signing/encryption certificates.
    You can do this with the java keytool command. Example commands below.
   
    keytool.exe -import -file "example_idp_signing_cert_file.cer" -alias idp_signing_cert -keystore "C:\path\to\step2\fedlet_directory\keystore.jks"
    keytool.exe -import -file "example_idp_encryption_cert_file.cer" -alias idp_encryption_cert -keystore "C:\path\to\step2\fedlet_directory\keystore.jks"
   
    You will be prompted to enter a password. Enter the UNENCRYPTED password you chose in step 10.
   
    Contact your IDP Administration team for the appropriate signing and or encryption certificates. It is very possible there
    will not be an encryption certificate, but it will be extremely likely there is a signing certificate.
	
	
13. Configure `c:\path\to\step2\fedlet_directory\samlv2-authenticator.properties`.

14. Restart the J2EE server instance for the changed files to be picked up.

## Implementation

Kinetic Request service items can be setup to require authentication or not, independent of how 
another service item is configured.  This allows some service items to be open to the public, while
ensuring that only authenticated users have access to other service items.

For service items that do require authentication, the service item must be configured to do so.
This can be accomplished using either the AR System Remedy User application, or the AR System
Mid-Tier web application.

Using one of the two applications, perform the following steps for each service item that must
use the authentication service:

1. Open the Kinetic Request Service Catalog Console form.
2. Select a service item that needs to use the authentication service.
3. Select the **Audit** tab.
4. Check the **Require Authentication** box.
5. Change the **Authentication Type** selection to *External*.
6. The **Authentication URL** is not used by this adapter, so it may be left blank.
7. Save the service item.


## Fedlet configuration files

  Quick note, almost all of these files contain sensitive information used to protect your single sign on authentication. Do not pass these files around.


  **debug folder** -				Contains a bunch of log files used to help debug the SAML communication. A lot of the error messages that will show up in these log files will be
									'googleable'. The most common issues that will happen will happen will be a wrong value for keypass.txt/storepass.txt (some gibberish about padding this or that),
									complaining that a signing/encrypting certificate wasn't trusted, expired certificates, etc.

  **FederationConfig.properties** - This file tells the SSO java plugin where stuff is like the keystore.jks file, the encrypted password files for keystore.jks
									(keypass.txt, storepass.txt), specifies the SAML logging directory (the debug folder) and the logging level for SAML related stuff.
									This file should rarely ever need to be changed other than the one time change made in step 7. There is also a lot of unused stuff / default values
									in here. The file is pretty well documented though when you open it up and take a look.

  **fedlet.cot** -					This file establishes a 'circle of trust' between the identity provider and the service provider (Kinetic Request).
									This file is very basic. The sun-fm-trusted-providers line should always contain the entityid of the service provider (search for entityid in the sp.xml file)
									and the entityid of the identity provider (search for entityid in the idp.xml file) seperated by a comma.

  **idp.xml** - 					This file describes how the IDP will communicate with us via SAML. This file will need to be modified for every implementation most likely to match
									the environment the IDP server is in (dev, qa, prod, etc.) as well as different setups between different kinds of IDPs. Example of how to create this file
									for an ADFS 2.0 IDP integration can been viewed here: https://wikis.forgerock.org/confluence/display/openam/OpenAM+and+ADFS2+configuration

  **idp-extended.xml** -			Extended information on how the IDP will communicate with us via SAML. This file was generated by installing OpenAM, creating an IDP & SP,
									and then choosing the 'create a fedlet' option. It is also where you go to specify the certificate aliases you created in the keystore file.
									Besides changing that, this files needs other modifications for most implementations.

  **keypass.txt** - 				This file contains the encrypted password for the keystore.jks file. This encryption is based on the encryption key specified in the FederationConfig.properties file (am.encryption.pwd).
									In order to generate a new encrypted password go to `https://<kinetic_request_deploy_directory>/kinetic/saml2/jsp/fedletEncode.jsp`

  **keystore.jks** -				This file will contain the certificates necessary for doing SAML service provider or identity provider signing or encrypting.
									This file can be generated for the first time by doing deploy step 12 when the keystore.jks file doesn't exist. 
									It says import in the command but it will also create a keystore file if it doesn't already exist.

  **sp.xml** -						This file describes how the service provider (Kinetic Request) will communicate with the identity provider. This file was created the same way the idp-extended.xml file was created.
									This file will need to be modified for each implementation/environment. The entityid can be anything but it needs to be shared with the identity provider software to establish a 'circle of trust'
									and remember it is also referenced in the fedlet.cot file. Makes the most sense just to make it the URL of kinetic request.

  **sp-extended.xml** - 			This file extends describing how the service provider will communicate with the identity provider. Created the same way as the sp.xml & idp-extended.xml files.
									Probably the only thing that will need to be changed for other implementations is the entityID, 'autofedAttribute' info, 'attributeMap' info 
									(this is what takes a 'claim' or rather describing piece of information about the logged in user provided by the identity provider, and lets the Kinetic Request SAML SSO plug-in
									know the unique id shared between remedy & the identity provider to do a lookup. Whatever piece of information from a claim you want to use (windows account name? e-mail address? some employee id number?)
									you need to map that one attribute to 'uid' for the Kinetic Request SAML SSO plugin...Maybe eventually that name will be configurable but I figured there was enough configurations as it was.

  **storepass.txt** -				Basically the same thing as the keypass.txt file...Slightly different purpose but basically the same. Basically.