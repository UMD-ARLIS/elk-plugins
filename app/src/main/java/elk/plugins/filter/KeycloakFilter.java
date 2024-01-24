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
//import org.keycloak.common.VerificationException;
import org.keycloak.representations.adapters.config.AdapterConfig;

/*
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
*/

import java.util.*;
import org.json.JSONObject;

// class name must match plugin name
@LogstashPlugin(name = "keycloak_filter")
public class KeycloakFilter implements Filter {
    public static final PluginConfigSpec<String> SOURCE_CONFIG = PluginConfigSpec.stringSetting("source", "authorization");
    public static final PluginConfigSpec<String> SERVER_CONFIG = PluginConfigSpec.stringSetting("server", null, false, false);
    public static final PluginConfigSpec<String> REALM_CONFIG = PluginConfigSpec.stringSetting("realm", null, false, false);
    public static final PluginConfigSpec<String> RESOURCE_CONFIG = PluginConfigSpec.stringSetting("resource", null, false, false);

    private String id;
    private String sourceField;
    private KeycloakDeployment deployment;

    public KeycloakFilter(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);

        AdapterConfig adapterConfig = new AdapterConfig();
        adapterConfig.setRealm(config.get(REALM_CONFIG));
        adapterConfig.setResource(config.get(RESOURCE_CONFIG));
        adapterConfig.setAuthServerUrl(config.get(SERVER_CONFIG));

        this.deployment = KeycloakDeploymentBuilder.build(adapterConfig);
    }

    @Override
    public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
        for (Event e : events) {
            Object f = e.getField(sourceField);

            if (f instanceof String) {
                String httpHeader = (String)f;
                JSONObject jsonHeader = new JSONObject(httpHeader);

                if (jsonHeader.has("x_token_auth"))
                {
                    String token = jsonHeader.getString("x_token_auth");

                    try{

                        var tok = AdapterTokenVerifier.verifyToken(token, this.deployment);
                        // passed
                        tok.getPreferredUsername(); // user name
                        tok.getSubject();           // keycloak user id
                        /*
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(this.keycloakPublicKey));
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        PublicKey publicKeyObj = kf.generatePublic(keySpec);

                        Jws<Claims> jwt = Jwts.parserBuilder()
                            .setSigningKey(publicKeyObj)
                            .build()
                            .parseClaimsJws(token);
                        */

                        e.setField("authorized", true);
                    }
                    catch (Exception ex)
                    {
                        e.setField("auth_error", ex.getMessage());
                        e.setField("authorized", false);
                    }
                }
                else
                {
                    e.setField("auth_error", "can't find auth token");
                    e.setField("authorized", false);
                }

                e.remove(sourceField);

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