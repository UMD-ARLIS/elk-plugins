package elk.plugins.filter;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.adapters.config.AdapterConfig;

/*
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
*/
import java.util.*;

// class name must match plugin name
@LogstashPlugin(name = "keycloak_filter")
public class KeycloakFilter implements Filter {
    public static final PluginConfigSpec<String> SOURCE_CONFIG = PluginConfigSpec.stringSetting("source", "authorization");
    public static final PluginConfigSpec<String> SERVER_CONFIG = PluginConfigSpec.stringSetting("server", null, false, true);
    public static final PluginConfigSpec<String> REALM_CONFIG = PluginConfigSpec.stringSetting("realm", null, false, true);
    public static final PluginConfigSpec<String> RESOURCE_CONFIG = PluginConfigSpec.stringSetting("resource", null, false, true);

    private String id;
    private String sourceField;
    private String realm;
    private String server;
    private String resource;
    //private static String keycloakPublicKey;

    //private Keycloak keyCloak;

    public KeycloakFilter(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.realm = config.get(REALM_CONFIG);
        this.server = config.get(SERVER_CONFIG);
        this.resource = config.get(RESOURCE_CONFIG);
        this.sourceField = config.get(SOURCE_CONFIG);

        /*
        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("http://localhost:8080/realms/userale-keycloak-demo/protocol/openid-connect/certs"))
            .build();

        String token = "ghfghfdhdhdfhdfghdhdfhdfhdfhhdf";
        keycloakPublicKey = "awdasdsadaefafafaef5df65d4f";
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(keycloakPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey = kf.generatePublic(keySpec);
        */
        
        /*
        this.keyCloak = KeycloakBuilder.builder()
            .serverUrl("https://sso.example.com/auth")
            .realm("example")
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .clientId("client")
            .clientSecret("secret")
            .build();
        */
    }

    @Override
    public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
        for (Event e : events) {
            Object f = e.getField(sourceField);

            if (f instanceof String) {
                //e.setField(sourceField, StringUtils.reverse((String)f));

                AdapterConfig config = new AdapterConfig();
                config.setRealm(this.realm);
                config.setResource(this.resource);
                config.setAuthServerUrl(this.server);

                KeycloakDeployment depl = KeycloakDeploymentBuilder.build(config);

                String httpHeader = (String)f;
                

                String tokenToVerify = "";

                try{
                    var tok = AdapterTokenVerifier.verifyToken(tokenToVerify, depl);
                    // passed
                    tok.getPreferredUsername(); // user name
                    tok.getSubject();           // keycloak user id

                    e.setField("authorized", true);
                }
                catch (VerificationException ex){
                    // failed
                    e.setField("authorized", false);
                }

                matchListener.filterMatched(e);
            }
        }

        return events;
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        Vector<PluginConfigSpec<?>> v = new Vector<PluginConfigSpec<?>>();
        v.add(SOURCE_CONFIG); 
        v.add(SERVER_CONFIG); 
        v.add(REALM_CONFIG); 
        v.add(RESOURCE_CONFIG);
    
       return Collections.list(v.elements());
    }

    @Override
    public String getId() {
        return this.id;
    }
}