package datawave.microservice.authorization.jsd;

import static datawave.microservice.authorization.keycloak.KeycloakDatawaveUserService.CACHE_NAME;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheConfig;

import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import datawave.security.authorization.SubjectIssuerDNPair;

/**
 * A helper class to allow calls to be cached using Spring annotations. Normally, these could just be methods in {@link JsdDatawaveUserService}. However, Spring
 * caching works by wrapping the class in a proxy, and self-calls on the class will not go through the proxy. By having a separate class with these methods, we
 * get a separate proxy that performs the proper cache operations on these methods.
 */
@CacheConfig(cacheNames = CACHE_NAME)
public class JsdDatawaveUserLookup {
    public final Logger logger = LoggerFactory.getLogger(getClass());
    private final JsdDULProperties jsdDULProperties;
    
    public JsdDatawaveUserLookup(JsdDULProperties jsdDULProperties) {
        this.jsdDULProperties = jsdDULProperties;
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
        logger.info("Inside JSD build user...");
        logger.info(String.format("DN Info:%s", dn.toString()));
        logger.info(String.format("Database Address:%s", jsdDULProperties.getDbAddr()));
        logger.info(String.format("Database Name:%s", jsdDULProperties.getDbName()));
        logger.info(String.format("Database User:%s", jsdDULProperties.getDbUser()));
        logger.info(String.format("Database Password:%s", jsdDULProperties.getDbPassword()));
        UserType userType = UserType.USER;
        
        List<String> auths = new ArrayList<String>();
        List<String> roles = new ArrayList<String>();
        
        try (Connection connection = getConnection()) {
            logger.info("Got connection, performing query...");
            
            int personGuid = getPersonGuid(connection, dn);
            
            // no user found matching the cert, cannot continue
            if (personGuid == -1) {
                return new DatawaveUser(dn, userType, null, null, null, System.currentTimeMillis());
            }
            
            // Get the Auths
            if (jsdDULProperties.isClearancesEnabled()) {
                List<String> clearances = getClearances(connection, personGuid);
                logger.info("Clearances:");
                clearances.stream().forEach(c -> logger.info(c));
                auths.addAll(clearances);
                
                if (jsdDULProperties.isClassRolesEnabled()) {
                    // Get the Roles
                    List<String> classRoles = getClassRoles(connection, clearances);
                    logger.info("Classification Roles:");
                    classRoles.stream().forEach(cr -> logger.info(cr));
                    roles.addAll(classRoles);
                }
            }
            
            if (jsdDULProperties.isDisseminationControlsEnabled()) {
                List<String> disseminationControls = getDisseminationControls(connection, personGuid);
                logger.info("Dissemination Controls:");
                disseminationControls.stream().forEach(dc -> logger.info(dc));
                auths.addAll(disseminationControls);
            }
            
            if (jsdDULProperties.isFineAccessControlsEnabled()) {
                List<String> fineAccessControls = getFineAccessControls(connection, personGuid);
                logger.info("Fine Access Controls:");
                fineAccessControls.stream().forEach(fac -> logger.info(fac));
                auths.addAll(fineAccessControls);
            }
            
            if (jsdDULProperties.isReleasableTosEnabled()) {
                List<String> releasableTos = executeQuery(connection, personGuid, "releasable_to", "releasable_to");
                logger.info("Releasable To:");
                releasableTos.stream().forEach(rt -> logger.info(rt));
                auths.addAll(releasableTos);
            }
            
            // User Type
            if (isNPE(connection, personGuid)) {
                userType = UserType.SERVER;
            }
            
        } catch (SQLException e) {
            logger.debug(e.toString());
        }
        
        return new DatawaveUser(dn, userType, "", auths, roles, null, System.currentTimeMillis());
    }
    
    protected String translateDN(String subjectDN) {
        int startIndex = subjectDN.contains("cn=") ? subjectDN.indexOf("cn=") + "cn=".length() : 0;
        return subjectDN.toLowerCase().substring(startIndex, subjectDN.indexOf(','));
    }
    
    /**
     * Create the connection with the Postgresql Database
     * 
     * @return
     * @throws SQLException
     */
    private Connection getConnection() throws SQLException {
        logger.info("creating connection to DB...");
        String url = String.format("jdbc:postgresql://%s/%s", jsdDULProperties.getDbAddr(), jsdDULProperties.getDbName());
        Properties props = new Properties();
        props.setProperty("user", jsdDULProperties.getDbUser());
        props.setProperty("password", jsdDULProperties.getDbPassword());
        
        return DriverManager.getConnection(url, props);
    }
    
    /**
     * Gets the person GUID using the subject CN field of the certificate. Currently comparing to the first name of the user.
     * 
     * @param connection
     * @param dn
     *            - certificate information
     * @return The integer representing the personGuid
     * @throws SQLException
     */
    private int getPersonGuid(Connection connection, SubjectIssuerDNPair dn) throws SQLException {
        logger.info("Getting the person GUID...");
        // This is intended to add a sub-query string, depending on route being used.
        String query = "select personguid from jsd_entities.person where %s;";
        
        if (jsdDULProperties.isUseCacFormat()) {
            String subQuery = "LOWER(namelast) = LOWER(?) AND LOWER(namefirst) = LOWER(?) AND LOWER(namemiddle) = LOWER(?) AND personguid = ?";
            query = String.format(query, subQuery);
        } else {
            String subQuery = "namefirst = ?";
            query = String.format(query, subQuery);
        }
        logger.info(String.format("Database Query:%s", query));
        
        int personGuid = -1;
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            if (jsdDULProperties.isUseCacFormat()) {
                // LAST.FIRST.MIDDLE.1234
                String subjectDN = translateDN(dn.subjectDN());
                String[] splitSubjectDN = subjectDN.split("\\.");
                stmt.setString(1, splitSubjectDN[0]);
                stmt.setString(2, splitSubjectDN[1]);
                stmt.setString(3, splitSubjectDN[2]);
                stmt.setInt(4, Integer.parseInt(splitSubjectDN[3]));
            } else {
                logger.info(translateDN(dn.subjectDN()));
                stmt.setString(1, translateDN(dn.subjectDN()));
            }
            logger.info(stmt.toString());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                personGuid = rs.getInt("personguid");
            }
            
            logger.info(String.format("Persion GUID:%s", personGuid));
            return personGuid;
        }
    }
    
    /**
     * Get the list of clearances from the database for the specific user.
     * 
     * @param conn
     * @param personGuid
     * @return
     * @throws SQLException
     */
    private List<String> getClearances(Connection conn, int personGuid) throws SQLException {
        logger.info("Getting the user clearances...");
        return executeQuery(conn, personGuid, "clearance", "clearance");
    }
    
    /**
     * Get the list of dissemination controls from the database for the specific user.
     * 
     * @param conn
     * @param personGuid
     * @return
     * @throws SQLException
     */
    private List<String> getDisseminationControls(Connection conn, int personGuid) throws SQLException {
        logger.info("Getting the user dissemenation controls...");
        return executeQuery(conn, personGuid, "dissemination_control", "dissemination_control");
    }
    
    /**
     * Get the list of fine access controls from the database for the specific user.
     * 
     * @param conn
     * @param personGuid
     * @return
     * @throws SQLException
     */
    private List<String> getFineAccessControls(Connection conn, int personGuid) throws SQLException {
        logger.info("Getting the user fine access controls...");
        return executeQuery(conn, personGuid, "fine_access_control", "fine_access_control");
    }
    
    /**
     * Executes the query against the mxs_aces schema,
     * 
     * @param conn
     * @param personGuid
     * @param table
     * @param column
     * @return
     * @throws SQLException
     */
    private List<String> executeQuery(Connection conn, int personGuid, String table, String column) throws SQLException {
        String query = String.format("select %s from mxs_aces.%s where jsdpersonid = ?;", column, table);
        logger.info(String.format("Database Query:%s", query));
        List<String> values = new ArrayList<String>();
        
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, personGuid);
            logger.info(stmt.toString());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String value = rs.getString(column);
                values.add(value);
            }
        }
        return values;
    }
    
    /**
     * Using the list of clearances, get a list of the role for each clearance.
     * 
     * @param conn
     * @param clearances
     * @return
     * @throws SQLException
     */
    private List<String> getClassRoles(Connection conn, List<String> clearances) throws SQLException {
        List<String> classRoles = new ArrayList<String>();
        String query = "select classificationname from mxs_common.classification_lu where classificationportionname in %s";
        query = String.format(query, convertListForSqlStmt(clearances));
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String value = rs.getString("classificationname");
                classRoles.add(value);
            }
        }
        return classRoles;
    }
    
    /**
     * Checks whether or not the proxied user is a non-person-entity or not.
     * 
     * @param conn
     * @param personGuid
     * @return
     * @throws SQLException
     */
    private boolean isNPE(Connection conn, int personGuid) throws SQLException {
        return executeQuery(conn, personGuid, "non_person_entity", "non_person_entity").size() == 0 ? false : true;
    }
    
    /**
     * Converts the list of clearances to a the following format for use in querying. ('X', 'X1', ... 'Xn')
     * 
     * @param myList
     * @return
     */
    private String convertListForSqlStmt(List<String> myList) {
        String returnVal = "(";
        for (int i = 0; i < myList.size(); i++) {
            String val = myList.get(i);
            returnVal += "'" + val + "'";
            if (i < myList.size() - 1) {
                returnVal += ",";
            }
            
            returnVal += ")";
        }
        logger.info(String.format("List conversion:%s", returnVal));
        return returnVal;
    }
}
