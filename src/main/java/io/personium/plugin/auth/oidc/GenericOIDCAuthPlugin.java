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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.RequiredTypeException;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * Implementation of GenericOIDCAuthPlugin
 */
public class GenericOIDCAuthPlugin extends OIDCAuthPluginBase {

    static Logger log = LoggerFactory.getLogger(GenericOIDCAuthPlugin.class);

    /** Prefix of property */
    static final String PREFIX_CONFIG_PROPERTY="io.personium.plugin.oidc.generic.";

    /** OpenID Connect Configuration Endpoint URL */
    static final String CONFIGURATION_ENDPOINT;

    /** Trusted Client Ids */
    static final List<String> TRUSTED_CLIENT_IDS;

    /** Customized plugin name */
    static final String CUSTOM_PLUGIN_NAME;

    /** Customized account type */
    static final String CUSTOM_ACCOUNT_TYPE;

    /** Customized account name key in claims */
    static final String CUSTOM_ACCOUNT_NAME_KEY;

    /** Customized grant type */
    static final String CUSTOM_GRANT_TYPE;

    static {
        Properties props = new Properties();
        try(InputStream is = GenericOIDCAuthPlugin.class.getClassLoader().getResourceAsStream("default.properties")) {
            if (is == null) {
                log.warn("Plugin default.properties is not found");
            }
            props.load(is);
        } catch(IOException e) {
            log.warn("Cannot load plugin default.properties", e);
        }

        String pluginConfigPath = (String)props.getProperty("config.filename");
        Properties configProps = new Properties();
        try(InputStream is = GenericOIDCAuthPlugin.class.getClassLoader().getResourceAsStream(pluginConfigPath)) {
            configProps.load(is);
        } catch (FileNotFoundException e) {
            log.warn("Plugin config is not found in plugin directory: " + pluginConfigPath);
        } catch (IOException e) {
            log.warn("Cannot load plugin config", e);
        }

        CONFIGURATION_ENDPOINT = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "configURL");
        String trustedClientIds = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "trustedClientIds");
        TRUSTED_CLIENT_IDS = Arrays.asList(trustedClientIds.split(" "));

        CUSTOM_PLUGIN_NAME = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "customPluginName", "Generic OIDC Plugin");
        CUSTOM_ACCOUNT_TYPE = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "customAccountType", "oidc:generic");
        CUSTOM_ACCOUNT_NAME_KEY = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "customAccountNameKey", "username");
        CUSTOM_GRANT_TYPE = configProps.getProperty(PREFIX_CONFIG_PROPERTY + "customGrantType", "urn:x-personium:oidc:generic");
    }

    /**
     * Constructor of GenericOIDCAuthPlugin
     */
    public GenericOIDCAuthPlugin() throws AuthPluginException {
        super(CONFIGURATION_ENDPOINT);
        log.info(CUSTOM_PLUGIN_NAME + " Loaded (" + CUSTOM_GRANT_TYPE + ")");
    }

    /**
     * Constructor of GenericOIDCAuthPlugin (without config properties)
     * @param issuerURL URL of issuer
     * @param configurationEndpoint URL of configurationEndpoint
     */
    public GenericOIDCAuthPlugin(String configurationEndpoint) throws AuthPluginException {
        super(configurationEndpoint);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return CUSTOM_PLUGIN_NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAccountType() {
        return CUSTOM_ACCOUNT_TYPE;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public String getGrantType() {
        return CUSTOM_GRANT_TYPE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected AuthenticatedIdentity parseClaimsToAuthenticatedIdentity(Claims claims) {
        AuthenticatedIdentity ai = new AuthenticatedIdentity();
        ai.setAccountName((String)claims.get(CUSTOM_ACCOUNT_NAME_KEY));
        ai.setAccountType(CUSTOM_ACCOUNT_TYPE);
        return ai;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("unchecked")
    boolean isProviderClientIdTrusted(Claims claims) {
        if (TRUSTED_CLIENT_IDS.contains("*")) return true;

        // Try to parse audience as ArrayList
        List<String> audiencesList = new ArrayList<String>();
        try {
            ArrayList<String> auds = claims.get("aud", ArrayList.class);
            audiencesList.addAll(auds);
        } catch (RequiredTypeException e ) {
            // get audience as String
            String audience = claims.getAudience();
            audiencesList.add(audience);
        }

        for (String client_id : TRUSTED_CLIENT_IDS) {
            if (audiencesList.contains(client_id)) return true;
        }

        return false;
    }

}
