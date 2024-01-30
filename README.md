# Repository for custom ELK stack plugins

## Compiling and deploying changes made in plugin Java code
The Logstash filter implements Logstash's Filter interface, therefore a compiled .jar of the Logstash codebase
is needed in order to create the filter. One is included in app\libs directory (version 8.13.0), but if another 
version is needed that version's codebase must be downloaded and compiled separately.

Further instructions can be found at [How to write a Java filter plugin](https://www.elastic.co/guide/en/logstash/current/java-filter-plugin.html).

1. From a command prompt pointing to the root directory (where gradlew.bat is located), run the following command:
        gradlew gem
The task will produce a gem file in the root directory of your plugin’s codebase with the name logstash-filter-keycloak_filter-1.0.gem.

2. Copy the generated gem file (should be located in the \app directory) to a folder that the docker container for Logstash will have access to.

3. Add the following lines to the Dockerfile for the Logstash docker container:
        ADD \<relative directory path of the gem file to Dockerfile\> /usr/share/logstash/plugins

        RUN logstash-plugin install --no-verify --local /usr/share/logstash/plugins/logstash-filter-keycloak_filter-1.0.gem

4. To configure Logstash to use the keycloak filter, modify Logstash.conf so that there is an entry in the filter section similar to this:
        filter {
            keycloak_filter {
                source => "\<the attribute name in the Logstash event that contains the http header information\>"
                resource => "\<the keycloak application name that the filter will be validating against\>"
                access_token => "\<the header attribute that contains the user\'s access token\>"
                realm => "\<the keycloak realm that the filter will be validating against\>"
                server => "\<the url of the keycloak server\>"
            }
        }

5. Build the Logstash container