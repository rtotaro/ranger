package org.apache.ranger.keycloakusersync;

import org.apache.log4j.Logger;
import org.apache.ranger.unixusersync.config.UserGroupSyncConfig;
import org.apache.ranger.usergroupsync.UserGroupSink;
import org.apache.ranger.usergroupsync.UserGroupSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;
import java.util.stream.Collectors;

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
                List<GroupRepresentation> userGroups = realm.users().get(userRepresentation.getId()).groups();
                sink.addOrUpdateUser(userRepresentation.getUsername(), userGroups.stream().map(groupRepresentation -> groupRepresentation.getName()).collect(Collectors.toList()));
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        });
    }
}
