package datawave.microservice.authorization.keycloak;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(KeycloakDULProperties.class)
@ConfigurationProperties(prefix = "keycloak.users")
public class KeycloakDULProperties {
    private String url = "https://login.eda.acca2datalab.us/auth/";
    private String realmName = "baby-yoda";
    private String clientId = "datawave-authentication";
    private String clientSecret = "WtL2v8SL3ZoFqp32U2YsekauGij95f4z";
    private String scope = "openid";
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public String getRealmName() {
        return realmName;
    }
    
    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public String getClientSecret() {
        return clientSecret;
    }
    
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
    
    public String getScope() {
        return scope;
    }
    
    public void setScope(String scope) {
        this.scope = scope;
    }
}
