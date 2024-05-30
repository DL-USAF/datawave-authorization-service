package datawave.microservice.authorization.keycloak;

import datawave.microservice.cached.CacheInspector;
import datawave.security.authorization.CachedDatawaveUserService;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUserInfo;
import datawave.security.authorization.SubjectIssuerDNPair;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;

import java.util.Collection;
import java.util.stream.Collectors;

import static datawave.microservice.authorization.keycloak.KeycloakDatawaveUserService.CACHE_NAME;

/** A version of the {@link CachedDatawaveUserService} that returns results from Keycloak */
@CacheConfig(cacheNames = CACHE_NAME)
public class KeycloakDatawaveUserService implements CachedDatawaveUserService {
  public static final String CACHE_NAME = "datawaveUsers";

  private final KeycloakDatawaveUserLookup keycloakDatawaveUserLookup;
  private final CacheInspector cacheInspector;

  public KeycloakDatawaveUserService(
      KeycloakDatawaveUserLookup keycloakDatawaveUserLookup, CacheInspector cacheInspector) {
    this.keycloakDatawaveUserLookup = keycloakDatawaveUserLookup;
    this.cacheInspector = cacheInspector;
  }

  @Override
  public Collection<DatawaveUser> lookup(Collection<SubjectIssuerDNPair> dns) {
    return dns.stream().map(keycloakDatawaveUserLookup::lookupUser).collect(Collectors.toList());
  }

  @Override
  public Collection<DatawaveUser> reload(Collection<SubjectIssuerDNPair> dns) {
    return dns.stream().map(keycloakDatawaveUserLookup::reloadUser).collect(Collectors.toList());
  }

  @Override
  public DatawaveUser list(String name) {
    return cacheInspector.list(CACHE_NAME, DatawaveUser.class, name.toLowerCase());
  }

  @Override
  public Collection<? extends DatawaveUserInfo> listAll() {
    return cacheInspector.listAll(CACHE_NAME, DatawaveUser.class).stream()
        .map(DatawaveUserInfo::new)
        .collect(Collectors.toList());
  }

  @Override
  public Collection<? extends DatawaveUserInfo> listMatching(String substring) {
    return cacheInspector.listMatching(CACHE_NAME, DatawaveUser.class, substring.toLowerCase())
        .stream()
        .map(DatawaveUserInfo::new)
        .collect(Collectors.toList());
  }

  @Override
  @CacheEvict
  public String evict(String name) {
    return "Evicted " + name;
  }

  @Override
  public String evictMatching(String substring) {
    int numEvicted =
        cacheInspector.evictMatching(CACHE_NAME, DatawaveUser.class, substring.toLowerCase());
    return "Evicted " + numEvicted + " entries from the cache.";
  }

  @Override
  @CacheEvict(allEntries = true)
  public String evictAll() {
    return "All entries evicted";
  }
}
