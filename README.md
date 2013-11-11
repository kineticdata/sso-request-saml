# Kinetic Request SAMLv2 Authentication

This project is a Kinetic Request single-sign-on adapter that authenticates users
using OpenSSO Fedlet with SAMLv2.

## Change Log

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

1. Copy the `dist/samlv2-authenticator.properties` file to the `<kinetic_request_deploy_directory>/WEB-INF/classes` 
   directory, and configure the properties. Properties are documented in the samlv2-authenticator.properties file.
   
2. Copy the dist/SAMLLanding.jsp file to the `<kinetic_request_deploy_directory>`
   
3. Copy the `dist/samlv2-authenticator.jar` & samlv2-dependencies.jar files to the 
   `<kinetic_request_deploy_directory>/WEB-INF/lib` directory.
   
4. Copy the `dist/fedlet` directory to a path of your choice, then document this path.

5. Add the -Dcom.sun.identity.fedlet.home java parameter to your J2EE server configuration to point to
   the path you chose in step 4. For example: -Dcom.sun.identity.fedlet.home="c:\fedlet_config_folder"
   
6. Configure the fedlet configuration files contained in the directory you chose in step 4.
   See the section below 'Fedlet Configuration' on how to configure these files.
      
7. Login to the Kinetic Request Admin Console and set the following web application properties:
   - **API Impersonate User** => `true (make sure the checkbox is checked)`
   - **SSO Adapter Class** => `com.kineticdata.request.authentication.SAML2Authenticator`
   - **SSO Adapter Properties** => `path/to/samlv2-authenticator.properties`

8. Restart the web server instance for the new files to be included.


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

  FederationConfig.properties - This file will very rarely need modification except for maybe the am.encryption.pwd property.
                                All properties are highly commented in the file.
								
  fedlet.cot                  - This is the 'circle of trust' file. For most implementations you should only need to modify the 
                                sun-fm-trusted-providers property. This property contains the entity IDs of Identity Providers
                                you wish to trust. These entity IDs must match exactly with what is 

  sp.xml                      - The sp.xml file is the 'service provider' configuration file.
  
  sp-extended.xml             -   
  
  idp.xml                     - There is a chance that you might be able to replace this file with the exported metadata from your
                                service provider without any modifications, but for some identity providers like ADFS 2.0 modification
								is necessary. Modification information for the idp.xml file for ADFS 2.0 can be found at the following link:
								https://wikis.forgerock.org/confluence/display/openam/OpenAM+and+ADFS2+configuration
  
  idp-extended.xml            - 