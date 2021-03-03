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

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * List of Jwks
 */
public class Jwks {

    /** Endpoint of openid configuration URL */
    String OpenIdConfigurationEndpointURL = null;

    /** Array of keyinfo */
    JSONArray keyArray = null;

    /**
     * Constructor of Jwks
     * @param endpoint 
     */
    public Jwks(final String endpoint) {
        this.OpenIdConfigurationEndpointURL = endpoint;
    }

    /**
     * Function for getting jwks_uri from remote (.well-known URL)
     * @param endpoint
     * @return jwks_uri
     * @throws AuthPluginException
     */
    private String getJwksUri(final String endpoint) throws AuthPluginException {
        try {
            return (String)PluginUtils.getHttpJSON(endpoint).get("jwks_uri");
        } catch(ClientProtocolException e) {
            // exception with HTTP procotol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "proper HTTP response");
        } catch(IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, endpoint, "");
        } catch(ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "JSON");
        }
    }

    /**
     * Function for getting jwks from remote (jsks_uri URL)
     * @return jwks
     * @throws AuthPluginException
     */
    private JSONArray getKeys() throws AuthPluginException {
        String endpoint = getJwksUri(OpenIdConfigurationEndpointURL);
        try {
            return (JSONArray)PluginUtils.getHttpJSON(endpoint).get("keys");
        } catch(ClientProtocolException e) {
            // exception with HTTP procotol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "proper HTTP response");
        } catch(IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, endpoint, "");
        } catch(ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "JSON");
        }
    }

    /**
     * Find key from key list
     * @param kid kid of Jwt header
     * @param alg alg of Jwt header
     * @return public key
     */
    public Key getKey(String kid, String alg) throws AuthPluginException {
        this.keyArray = getKeys();
        for (Object o : keyArray) {
            if (!(o instanceof JSONObject)) continue;
            JSONObject k = (JSONObject)o;
            
            String compKid = (String)k.get("kid");
            String compAlg = (String)k.get("alg");
            if (!compKid.equals(kid)) continue;

            if (alg != null && !compAlg.equals(alg)) continue;

            String kty = (String)k.get("kty");
            KeySpec ks = null;


            try {
                KeyFactory kf = KeyFactory.getInstance(kty);
                switch(kty) {
                    case "RSA":
                        BigInteger n = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get("n")));
                        BigInteger e = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get("e")));
                        ks = new RSAPublicKeySpec(n, e);
                    break;
                    case "EC":
                        AlgorithmParameters params  = AlgorithmParameters.getInstance("EC");
                        if (!"P-256".equals(k.get("crv"))) {
                            throw new Exception(String.format("curve %s is not supported", (String)k.get("crv")));
                        }
                        params.init(new ECGenParameterSpec("secp256k1"));
                        BigInteger x = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get("x")));
                        BigInteger y = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get("y")));
                        ECPoint w = new ECPoint(x, y);
                        ks = new ECPublicKeySpec(w, params.getParameterSpec(ECParameterSpec.class));
                    break;
                    default:
                        throw OidcPluginException.UNEXPECTED_VALUE.create(kty);
                }
                return kf.generatePublic(ks);
            } catch(NoSuchAlgorithmException|InvalidParameterSpecException e) {
                throw OidcPluginException.UNEXPECTED_VALUE.create();
            } catch(InvalidKeySpecException e) {
                throw OidcPluginException.INVALID_KEY.create(kty);
            } catch(Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }
            
        // there is no key
        throw OidcPluginException.INVALID_ID_TOKEN.create("No supported key is found from jwks_uri. ID Token header value is invalid.");
    }
}
