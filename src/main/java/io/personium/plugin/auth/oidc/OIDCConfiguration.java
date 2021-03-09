package io.personium.plugin.auth.oidc;

import java.io.IOException;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.utils.PluginUtils;


public class OIDCConfiguration {

    Jwks jwks = null;
    private String jwksURI = null;
    private String issuer = null;

    public OIDCConfiguration(String configurationEndpoint) throws AuthPluginException {
        this.reload(configurationEndpoint);
    }

    /**
     * Function for loading OIDC configuration from remote (.well-known URL)
     * 
     * @param endpoint
     * @throws AuthPluginException
     */
    public void reload(String configurationEndpoint) throws AuthPluginException {
        try {
            JSONObject configurationJSON = PluginUtils.getHttpJSON(configurationEndpoint);
            this.jwksURI = (String) configurationJSON.get("jwks_uri");
            this.issuer = (String) configurationJSON.get("issuer");
            this.jwks = new Jwks(getKeys(this.jwksURI));
        } catch (ClientProtocolException e) {
            // exception with HTTP procotol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(configurationEndpoint, "proper HTTP response");
        } catch (IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, configurationEndpoint, "");
        } catch (ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(configurationEndpoint, "JSON");
        }
    }

    /**
     * Function for getting jwks from remote (jsks_uri URL)
     * 
     * @return jwks
     * @throws AuthPluginException
     */
    private JSONArray getKeys(String jwksURL) throws AuthPluginException {
        try {
            return (JSONArray) PluginUtils.getHttpJSON(jwksURL).get("keys");
        } catch (ClientProtocolException e) {
            // exception with HTTP procotol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURL, "proper HTTP response");
        } catch (IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, jwksURL, "");
        } catch (ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURL, "JSON");
        }
    }

    public Jwks getJwks() {
        return this.jwks;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public JwksResolver getResolver() {
        return new JwksResolver(this.jwks);
    }

}
