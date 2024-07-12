package datawave.microservice.authorization.keycloak;

import static datawave.microservice.authorization.keycloak.KeycloakDatawaveUserService.CACHE_NAME;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.bouncycastle.util.Strings;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheConfig;

import com.beust.jcommander.internal.Lists;
import com.google.common.collect.HashMultimap;
import com.google.gson.GsonBuilder;
import com.hazelcast.org.json.JSONObject;

import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import datawave.security.authorization.SubjectIssuerDNPair;

/**
 * A helper class to allow calls to be cached using Spring annotations. Normally, these could just be methods in {@link KeycloakDatawaveUserService}. However,
 * Spring caching works by wrapping the class in a proxy, and self-calls on the class will not go through the proxy. By having a separate class with these
 * methods, we get a separate proxy that performs the proper cache operations on these methods.
 */
@CacheConfig(cacheNames = CACHE_NAME)
public class KeycloakDatawaveUserLookup {
    public final Logger logger = LoggerFactory.getLogger(getClass());
    private final KeycloakDULProperties keycloakDULProperties;
    
    public KeycloakDatawaveUserLookup(KeycloakDULProperties keycloakDULProperties) {
        this.keycloakDULProperties = keycloakDULProperties;
    }
    
    // @Cacheable(key = "#dn.toString()")
    public DatawaveUser lookupUser(SubjectIssuerDNPair dn) {
        return buildUser(dn);
    }
    
    // @Cacheable(key = "#dn.toString()")
    public DatawaveUser reloadUser(SubjectIssuerDNPair dn) {
        return buildUser(dn);
    }
    
    private DatawaveUser buildUser(SubjectIssuerDNPair dn) {
        logger.info("Inside Keycloak build user...");
        logger.info(String.format("Keycloak URL:%s", keycloakDULProperties.getUrl()));
        logger.info(String.format("Keycloak Realm Name:%s", keycloakDULProperties.getRealmName()));
        logger.info(String.format("Keycloak Client ID:%s", keycloakDULProperties.getClientId()));
        logger.info(String.format("Keycloak Client Secret:%s", keycloakDULProperties.getClientSecret()));
        logger.info(String.format("DN Info:", dn.toString()));
        UserType userType = UserType.USER;
        
        // String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", keycloakDULProperties.getUrl(), keycloakDULProperties.getRealmName());
        // String userInfoUrl = String.format("%s/realms/%s/protocol/openid-connect/userInfo", keycloakDULProperties.getUrl(),
        // keycloakDULProperties.getRealmName());
        //
        // try {
        // HttpClient client = HttpClient.newHttpClient();
        //
        // JSONObject data = new JSONObject();
        // data.put("client_id", keycloakDULProperties.getClientId());
        // data.put("client_secret", keycloakDULProperties.getClientSecret());
        // data.put("grant_type", "password");
        // data.put("scope", keycloakDULProperties.getScope());
        //
        //
        // HttpRequest request = HttpRequest.newBuilder(new URI(tokenUrl))
        // .header("Content-Type", "application/json")
        // .POST(BodyPublishers.ofString(data.toString()))
        // .build();
        //
        // HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        //
        // logger.info(String.format("Status Code: %s", response.statusCode()));
        // } catch (URISyntaxException e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // } catch (IOException e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // } catch (InterruptedException e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        
        Keycloak keycloak = KeycloakBuilder.builder().serverUrl(keycloakDULProperties.getUrl()).realm(keycloakDULProperties.getRealmName())
                        .grantType(OAuth2Constants.CLIENT_CREDENTIALS).scope(keycloakDULProperties.getScope()).clientId(keycloakDULProperties.getClientId())
                        .clientSecret(keycloakDULProperties.getClientSecret())
                        .resteasyClient(new ResteasyClientBuilderImpl().disableTrustManager().connectionPoolSize(10).build()).build();
        
        logger.info("BEFORE USER RESOURCE CALL");
        UsersResource usersResource = keycloak.realm(keycloakDULProperties.getRealmName()).users();
        usersResource.list().stream().forEach(u -> display(u));
        
        // logger.info("BEFORE GROUP RESOURCE CALL");
        // GroupsResource groupsResource = keycloak.realm(keycloakDULProperties.getRealmName()).groups();
        // logger.info(String.format("Cert DN:%s", translateDN(dn.subjectDN())));
        // groupsResource.groups().forEach(g -> logger.info(String.format("Group:%s", g.getName())));
        
        Optional<UserRepresentation> foundUserOptional = usersResource.list().stream().filter(u -> u.getAttributes() != null)
                        .filter(u -> u.getAttributes().get("usercertificate").get(0).toLowerCase().equals(translateDN(dn.subjectDN()))).findFirst();
        
        if (foundUserOptional.isPresent()) {
            logger.info("Found a user that matches the DN of the passed in certificate.");
            UserRepresentation foundUser = foundUserOptional.get();
            List<String> auths = Lists.newArrayList();
            List<String> roles = Lists.newArrayList();
            logger.info(new GsonBuilder().setPrettyPrinting().create().toJson(foundUser));
            List<GroupRepresentation> groupRepresentationList = usersResource.get(foundUser.getId()).groups();
            logger.info(new GsonBuilder().setPrettyPrinting().create().toJson(groupRepresentationList));
            for (GroupRepresentation gr : groupRepresentationList) {
                logger.info(gr.getName() + " found for user " + foundUser.getUsername());
            }
            auths.addAll(groupRepresentationList.stream().filter(g -> !g.getPath().startsWith("/SAP_ACCESS_2/")).map(GroupRepresentation::getName)
                            .filter(name -> !name.startsWith("ROLE_")).collect(Collectors.toList()));
            List<String> pathsForSap = groupRepresentationList.stream().filter(g -> g.getPath().startsWith("/SAP_ACCESS_2/")).map(GroupRepresentation::getPath)
                            .collect(Collectors.toList());
            for (String path : pathsForSap) {
                logger.info(path);
                String[] pathSplit = path.split("/");
                logger.info(new GsonBuilder().setPrettyPrinting().create().toJson(pathSplit));
                String access = pathSplit[2];
                String program = pathSplit[3];
                auths.add(program + "_" + access);
            }
            roles.addAll(groupRepresentationList.stream().map(GroupRepresentation::getName).filter(name -> name.startsWith("ROLE_"))
                            .map(name -> name.replace("ROLE_", "")).collect(Collectors.toList()));
            logger.info("BEFORE RETURN");
            return new DatawaveUser(dn, userType, foundUser.getEmail(), auths, roles, null, System.currentTimeMillis());
        } else
            return new DatawaveUser(dn, UserType.SERVER, "", null, null, null, System.currentTimeMillis());
    }
    
    protected String translateDN(String subjectDN) {
        int startIndex = subjectDN.contains("cn=") ? subjectDN.indexOf("cn=") + "cn=".length() : 0;
        return subjectDN.toLowerCase().substring(startIndex, subjectDN.indexOf(','));
    }
    
    private void display(UserRepresentation user) {
        System.out.println(String.format("Username:%s", user.getUsername() != null ? user.getUsername() : "null"));
        System.out.println(String.format("Attributes:%s", user.getAttributes() != null ? user.getAttributes() : "null"));
    }
}
