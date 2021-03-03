/**
 * Personium
 * Copyright 2021 Personium Project Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.personium.plugin.auth.oidc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import io.jsonwebtoken.Claims;
import io.personium.plugin.base.PluginConfig;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * Test implementation of GenericOIDCAuthPlugin
 */
public class KeyCloakOIDCAuthPlugin extends GenericOIDCAuthPlugin {

    /** HostURL used when no URL is specified */
    static final String DEFAULT_HOST_URL;

    /** Realm name used when no realm is specified */
    static final String DEFAULT_REALM_NAME;

    /** Default config name */
    static final String DEFAULT_CONFIG_NAME = "keycloak";

    /** Trusted client ids */
    static final List<String> TRUSTED_CLIENT_IDS;


    static {
        Properties props = new Properties();
        try(InputStream is = ClassLoader.getSystemResourceAsStream("default.properties")) {
            props.load(is);
        } catch( IOException e ) {
            e.printStackTrace();
        }

        Path pluginConfigPath = Paths.get(PluginConfig.getPluginPath(), (String)props.getProperty("config.filename"));

        Properties configProps = new Properties();
        try(InputStream is = new FileInputStream(pluginConfigPath.toString())) {
            configProps.load(is);
        } catch (FileNotFoundException e) {
            System.out.println("config cannot be loaded:" + pluginConfigPath);
        } catch( IOException e ) {
            e.printStackTrace();
        };

        DEFAULT_HOST_URL = configProps.getProperty("io.personium.core.oidc.keycloak.hostUrl");
        DEFAULT_REALM_NAME = configProps.getProperty("io.personium.core.oidc.keycloak.realm");
        String trustedClientIds = configProps.getProperty("io.personium.core.oidc.keycloak.trustedClientIds");
        TRUSTED_CLIENT_IDS = Arrays.asList(trustedClientIds.split(" "));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAccountType() {
        return "oidc:testkeycloak";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getGrantType() {
        return "urn:x-personium:oidc:testkeycloak";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected AuthenticatedIdentity parseClaimsToAuthenticatedIdentity(Claims claims) {
        AuthenticatedIdentity ai = new AuthenticatedIdentity();
        ai.setAccountName((String)claims.get("preferred_username"));
        ai.setAccountType("oidc:testkeycloak");
        return ai;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    boolean isProviderClientIdTrusted(String audience) {
        return (TRUSTED_CLIENT_IDS.contains("*") || TRUSTED_CLIENT_IDS.contains(audience));
    }

    /**
     * Constructor of KeyCloakOIDCAuthPlugin
     */
    public KeyCloakOIDCAuthPlugin() {
        this(DEFAULT_HOST_URL, DEFAULT_REALM_NAME);
    }

    /**
     * Constructor of KeyCloakOIDCAuthPlugin with params
     * @param hostURL URL of keycloak host (ex: http://kc.example.com:8080/)
     * @param realm name of realm
     */
    public KeyCloakOIDCAuthPlugin(String hostURL, String realm) {
        super(
            hostURL + "auth/realms/" + realm,
            hostURL + "auth/realms/" + realm + "/.well-known/openid-configuration"
            );
    }
}
