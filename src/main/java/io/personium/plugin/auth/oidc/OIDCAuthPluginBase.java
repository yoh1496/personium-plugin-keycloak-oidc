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

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import io.personium.plugin.base.PluginLog;
import io.personium.plugin.base.auth.AuthConst;
import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * Base of OIDCAuthPlugin
 */
public abstract class OIDCAuthPluginBase implements AuthPlugin {

    /** to String. */
    public static final String PLUGIN_TOSTRING = "Generic Open ID Connect Authentication";

    /** id token */
    public static final String KEY_TOKEN = "id_token";

    /** Issuer the id_token must contain */
    private String OIDCIssuer = null;

    /** URL of well-known openid-configuration for IdP */
    private String OIDCEndpointURL = null;

    /**
     * Constructor of OIDCAuthPlugin
     * @param OIDCIssuer Issuer the id_token must contain
     * @param OIDCEndpointURL URL of well-known openid-configuration for IdP
     */
    protected OIDCAuthPluginBase(String OIDCIssuer, String OIDCEndpointURL) {
        this.OIDCIssuer = OIDCIssuer;
        this.OIDCEndpointURL = OIDCEndpointURL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return PLUGIN_TOSTRING;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getType() {
        return AuthConst.PLUGIN_TYPE;
    }

    /**
     * Define method for generating AuthenticatedIdentity from claims
     * @param claim
     * @return AuthenticatedIdentity
     */
    abstract protected AuthenticatedIdentity parseClaimsToAuthenticatedIdentity(Claims claims);

    /**
     * Abstract method for determining the provided audience is trusted
     * @param audience
     * @return
     */
    abstract boolean isProviderClientIdTrusted(String audience);

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticatedIdentity authenticate(Map<String, List<String>> body) throws AuthPluginException {
        if (body == null) {
            OidcPluginException.REQUIRED_PARAM_MISSING.create("Body");
        }

        String idToken = null;
        
        // get idToken from body
        List<String> idTokenList = body.get(KEY_TOKEN);
        if (idTokenList == null) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(KEY_TOKEN);
        }
        idToken = idTokenList.get(0);
        if (StringUtils.isEmpty(idToken)) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(KEY_TOKEN);
        }

        Jwks jwks = new Jwks(this.OIDCEndpointURL);
        JwksResolver jwksResolver = new JwksResolver(jwks);
        Jws<Claims> jws = null;

        try {
            jws = Jwts.parserBuilder().setSigningKeyResolver(jwksResolver).build().parseClaimsJws(idToken);
            // parse LineIdToken
        } catch (ExpiredJwtException e) {
            // Is not the token expired
            Date expiration = e.getClaims().getExpiration();
            throw OidcPluginException.EXPIRED_ID_TOKEN.create(expiration.getTime());
        } catch (MalformedJwtException | IllegalArgumentException e) {
            e.printStackTrace();
            throw OidcPluginException.INVALID_ID_TOKEN.create("malformed jwt token is passed");
        } catch (SignatureException e ) {
            // IdToken contains wrong signature
            throw OidcPluginException.INVALID_ID_TOKEN.create("ID Token sig value is invalid");
        } catch (Exception e) {
            throw OidcPluginException.INVALID_ID_TOKEN.create(e.getMessage());
        }

        // Does the token contain specified issuer
        Claims claims = jws.getBody();
        String issuer = claims.getIssuer();
        if (!issuer.equals(this.OIDCIssuer)) {
            PluginLog.OIDC.INVALID_ISSUER.params(issuer).writeLog();
            throw OidcPluginException.AUTHN_FAILED.create();
        }

        // Does the token contain channelId as aud
        String audience = claims.getAudience();
        if (!this.isProviderClientIdTrusted(audience)) {
            throw OidcPluginException.WRONG_AUDIENCE.create(audience);
        }

        return this.parseClaimsToAuthenticatedIdentity(claims);
    }
}
