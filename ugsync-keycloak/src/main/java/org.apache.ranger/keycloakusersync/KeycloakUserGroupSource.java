package org.apache.ranger.keycloakusersync;

import org.apache.log4j.Logger;
import org.apache.ranger.unixusersync.config.UserGroupSyncConfig;
import org.apache.ranger.usergroupsync.UserGroupSink;
import org.apache.ranger.usergroupsync.UserGroupSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;

public class KeycloakUserGroupSource implements UserGroupSource {

    private static final Logger LOG = Logger.getLogger(KeycloakUserGroupSource.class);


    private Keycloak keycloak;

    public static void main(String[] args) throws Throwable {
        KeycloakUserGroupSource KCBuilder = new KeycloakUserGroupSource();

        KCBuilder.init();

        UserGroupSyncConfig userGroupSyncConfig = UserGroupSyncConfig.getInstance();

        UserGroupSink ugSink = userGroupSyncConfig.getUserGroupSink();

        LOG.info("initializing sink: " + ugSink.getClass().getName());
        ugSink.init();

        KCBuilder.updateSink(ugSink);
    }


    @Override
    public void init() throws Throwable {
        keycloak = Keycloak.getInstance(
                "http://localhost:8080/auth",
                "master",
                "admin",
                "admin",
                "admin-cli");
    }

    @Override
    public boolean isChanged() {
        return true;
    }

    @Override
    public void updateSink(UserGroupSink sink) throws Throwable {
        RealmResource realm = keycloak.realm("Customers");
        List<UserRepresentation> users = realm.users().list();
        users.stream().forEach(userRepresentation -> {
            try {
                sink.addOrUpdateUser(userRepresentation.getId(),userRepresentation.getGroups());
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        });
    }
}
