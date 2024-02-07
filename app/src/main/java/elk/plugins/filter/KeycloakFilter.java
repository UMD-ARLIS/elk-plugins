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
import org.keycloak.representations.adapters.config.AdapterConfig;

import java.util.*;
import org.json.JSONObject;

// class name must match plugin name
@LogstashPlugin(name = "keycloak_filter")
public class KeycloakFilter implements Filter {
    public static final PluginConfigSpec<String> REALM_CONFIG = PluginConfigSpec.stringSetting("realm", null, false, true);
    public static final PluginConfigSpec<String> SOURCE_CONFIG = PluginConfigSpec.stringSetting("source", null, false, true);
    public static final PluginConfigSpec<String> SERVER_CONFIG = PluginConfigSpec.stringSetting("server", null, false, true);
    public static final PluginConfigSpec<String> RESOURCE_CONFIG = PluginConfigSpec.stringSetting("resource", null, false, true);
    public static final PluginConfigSpec<Boolean> AUTO_REMOVE_CONFIG = PluginConfigSpec.booleanSetting("auto_remove", false, false, false);
    public static final PluginConfigSpec<String> ACCESS_TOKEN_CONFIG = PluginConfigSpec.stringSetting("access_token", "x_token_auth", false, true);

    private String id;
    private String sourceField;
    private boolean autoRemove;
    private String accessTokenField;
    private KeycloakDeployment deployment;

    public KeycloakFilter(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);
        this.autoRemove = config.get(AUTO_REMOVE_CONFIG);
        this.accessTokenField = config.get(ACCESS_TOKEN_CONFIG);

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

                if (jsonHeader.has(this.accessTokenField))
                {
                    String token = jsonHeader.getString(this.accessTokenField);

                    try {
                        var tok = AdapterTokenVerifier.verifyToken(token, this.deployment);
                        tok.getPreferredUsername(); // user name
                        tok.getSubject();          // keycloak user id

                        // passed, but only add the "authorized" field if
                        // AUTO_REMOVE is false, otherwise remove it if it
                        // is available
                        if (this.autoRemove) 
                            e.remove("authorized");
                        else
                            e.setField("authorized", true);
                    }
                    catch (Exception ex)
                    {
                        e.setField("auth_error", ex.getMessage());
                        e.setField("authorized", false);
                    }

                    // remove the keycloak access token from the header
                    jsonHeader.remove(this.accessTokenField);
                    e.setField(sourceField, jsonHeader.toString());
                }
                else
                {
                    e.setField("auth_error", "can't find auth token");
                    e.setField("authorized", false);
                }

                matchListener.filterMatched(e);
            }
        }

        // if AUTO_REMOVE is true, then automatically remove all unauthorized events
        if (this.autoRemove) events.removeIf(e -> e.getField("authorized") != null && (boolean)e.getField("authorized") == false);

        return events;
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        Vector<PluginConfigSpec<?>> v = new Vector<PluginConfigSpec<?>>();
        v.add(REALM_CONFIG); 
        v.add(SOURCE_CONFIG); 
        v.add(SERVER_CONFIG); 
        v.add(RESOURCE_CONFIG);
        v.add(AUTO_REMOVE_CONFIG);
        v.add(ACCESS_TOKEN_CONFIG);
    
       return Collections.list(v.elements());
    }

    @Override
    public String getId() {
        return this.id;
    }
}