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

1. Copy the `dist/remote_user-authenticator.properties` file to the `<kinetic_request_deploy_directory>/WEB-INF/classes` 
   directory, and configure the properties. Properties are documented in the remote_user-authenticator.properties file.
   
2. Copy the `dist/REMOTE_USER-authenticator.jar` file to the `<kinetic_request_deploy_directory>/WEB-INF/lib` 
   directory.
   
3. Login to the Kinetic Request Admin Console and set the following web application properties:
   - **API Impersonate User** => `true (make sure the checkbox is checked)`
   - **SSO Adapter Class** => `com.kineticdata.request.authentication.remoteuser.RemoteUserAuthenticator`
   - **SSO Adapter Properties** => `path/to/remote_user-authenticator.properties`
   
4. Ensure your J2EE server does not overwrite the REMOTE_USER HTTP header. With Tomcat for example you need to
   place: tomcatAuthentication="false" in the connector node inside the server.xml file.
   
5. Ensure your J2EE server cannot be accessed directly by end users. End users should only be able to access the
   J2EE server through the reverse proxy. This SSO plugin implicitly trusts what is put into the REMOTE_USER HTTP header.
   
6. Restart the web server instance for the new files to be included.


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