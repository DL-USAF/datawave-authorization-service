package datawave.microservice.authorization.keycloak;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import datawave.microservice.cached.CacheInspector;

/**
 * Configuration to supply beans for the {@link KeycloakDatawaveUserService}. This configuration is only active when the "keycloak" profile is selected. This
 * profile is used for retrieving entity information from Keycloak
 */
@Configuration
@EnableCaching
@Profile("keycloak")
public class KeycloakDatawaveUserServiceConfiguration {
    @Bean
    public KeycloakDatawaveUserService keycloakDatawaveUserService(KeycloakDatawaveUserLookup keycloakDatawaveUserLookup, CacheInspector cacheInspector) {
        return new KeycloakDatawaveUserService(keycloakDatawaveUserLookup, cacheInspector);
    }
    
    @Bean
    public KeycloakDatawaveUserLookup keycloakDatawaveUserLookup(KeycloakDULProperties keycloakDULProperties) {
        return new KeycloakDatawaveUserLookup(keycloakDULProperties);
    }
    
    @Bean
    public KeycloakDULProperties keycloakDULProperties() {
        return new KeycloakDULProperties();
    }
}
