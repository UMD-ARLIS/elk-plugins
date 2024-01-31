
# Repository for custom ELK stack plugins

The Logstash filter implements Logstash's Filter interface, therefore a compiled .jar of the Logstash codebase is needed in order to create the filter. One is included in app\libs directory (version 8.13.0), but if another version is needed that version's codebase must be downloaded and compiled separately.

Further instructions can be found at [How to write a Java filter plugin](https://www.elastic.co/guide/en/logstash/current/java-filter-plugin.html).

  
## Compiling and deploying Keycloak Filter changes made in plugin Java code
1. From a command prompt pointing to the root directory (where gradlew.bat is located), run the following command:

	> gradlew gem --no-daemon

	The task will produce a gem file in the root directory of your plugin’s codebase with the name logstash-filter-keycloak_filter-1.0.gem

2. Copy the generated gem file (should be located in the \app directory) to a folder that the docker container for Logstash will have access to

3. Add the following lines to the Dockerfile for the Logstash docker container:

	> ADD \<relative  directory  path  of  the  gem  file  to  Dockerfile\> /usr/share/logstash/plugins<br/>
	RUN logstash-plugin install --no-verify --local /usr/share/logstash/plugins/logstash-filter-keycloak_filter-1.0.gem

	A sample Dockerfile is included in the samples\logstash folder

4. To configure Logstash to use the keycloak filter, modify Logstash.conf so that there is an entry in the filter section similar to this:

	```yaml
	filter {
		keycloak_filter {
			source => "<the Logstash event's attribute that contains the http header>"
			resource => "<the keycloak application that the filter will be validating against>"
			access_token => "<the  header  attribute  that  contains  the  user's  access  token>"
			realm => "<the keycloak realm that the filter will be validating against>"
			server => "<the url of the keycloak server>"
			auto_remove => "<automatically remove unauthorized Logstash events (not required)>"
		}
	}
5. Build the Logstash container

## Additional Info
1. In build.gradle the variable LOGSTASH_CORE_PATH is defined in gradle.properties. It represents the directory path of the logstash-core directory in the source code for Logstash.

2. In build.gradle the call
	> file("VERSION").text.trim()

	uses the file VERSION in the app directory. Update this file whenever the version of the plugin filter needs to be changed.

3. When executing gradlew gem be sure to include --no-daemon. This will cause the gradle daemon to terminate when complete, preventing certain files from being locked and inaccessible

4. When auto_remove is set to false the Logstash the unauthorized Logstash event will not be removed from the pipeline.