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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CachingHttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.testcontainers.containers.BindMode;
import org.testcontainers.utility.DockerImageName;

import io.personium.plugin.base.PluginConfig.OIDC;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;
import io.personium.plugin.base.utils.ProxyUtils;
import io.personium.test.categories.Unit;

/**
 * Unit test for OidcPluginExceptionTest
 */
@Category({ Unit.class })
public class GenericOIDCAuthPluginTest {

    @ClassRule
    public static KeyCloakContainer kcContainer = new KeyCloakContainer(DockerImageName.parse("jboss/keycloak:12.0.2"))
            .withExposedPorts(8080)
            .withClasspathResourceMapping("keycloak_realm.json", "/tmp/keycloak_realm.json", BindMode.READ_ONLY)
            // .withEnv("KEYCLOAK_USER", "admin")
            // .withEnv("KEYCLOAK_PASSWORD", "password")
            .withEnv("KEYCLOAK_IMPORT", "/tmp/keycloak_realm.json");

    /**
     * Testing whether you can create specified type of exception
     */
    @Test
    public void testingForCreatingSpecifiedException() {
        AuthPluginException e = OidcPluginException.INVALID_KEY.create("testMessage");
        assertEquals(e.getMessage(), "OpenID Connect Invalid Key. (testMessage)");
    }

    /**
     * Test with keycloak
     */
    @Test
    // @Ignore
    public void testingWithKeyCloak() {
        String address = kcContainer.getHost();
        Integer port = kcContainer.getMappedPort(8080);

        String kcOrigin = "http://" + address + ":" + port + "/";

        try {
            GenericOIDCAuthPlugin plugin = new GenericOIDCAuthPlugin(
                    kcOrigin + "auth/realms/test/.well-known/openid-configuration");

            Map<String, List<String>> body = new HashMap<String, List<String>>();
            try {
                plugin.authenticate(body);
                fail("AuthPluginException is not called");
            } catch (Exception e) {
                assertEquals("Required parameter [id_token] missing.", e.getMessage());
            }

            // get id_token
            HttpPost post = new HttpPost(kcOrigin + "auth/realms/test/protocol/openid-connect/token");
            ArrayList<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "password"));
            params.add(new BasicNameValuePair("client_id", "oidctestclient"));
            params.add(new BasicNameValuePair("client_secret", "6cbd79e9-c387-4c72-9a1e-319441d44a81"));
            params.add(new BasicNameValuePair("username", "testuser"));
            params.add(new BasicNameValuePair("password", "passw0rd"));
            params.add(new BasicNameValuePair("response_type", "id_token"));
            params.add(new BasicNameValuePair("scope", "openid"));
            try {
                post.setEntity(new UrlEncodedFormEntity(params));
            } catch (Exception e) {
                fail(e.getMessage());
            }

            HttpResponse res = null;
            CloseableHttpClient httpClient = null;
            JSONObject jsonObj = null;
            try {
                if (ProxyUtils.isProxyHost()) {
                    httpClient = ProxyUtils.proxyHttpClient();
                    post.setConfig(ProxyUtils.getRequestConfig());
                } else {
                    httpClient = CachingHttpClientBuilder.create().build();
                }
                res = httpClient.execute(post);

                // try (InputStream is = res.getEntity().getContent()) {
                String bodyStr = EntityUtils.toString(res.getEntity(), "utf-8");
                System.out.println(bodyStr);
                jsonObj = (JSONObject) new JSONParser().parse(bodyStr);
            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            } finally {
                try {
                    httpClient.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    fail(e.getMessage());
                }
            }

            body.put("id_token", Arrays.asList(new String[] { (String) jsonObj.get("id_token") }));

            try {
                AuthenticatedIdentity ai = plugin.authenticate(body);
                assertEquals("testuser", ai.getAccountName());
                assertEquals(plugin.getAccountType(), ai.getAccountType());
            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        } catch (AuthPluginException e) {
            fail(e.getMessage());
        }

    }

    /**
     * Testing whether clientId in property file is treat as trusted
     */
    @Test
    @Ignore
    public void testingIsProviderClientIdTrusted() {
        assert (OIDC.isProviderClientIdTrusted("keycloak", "dummy-client2"));
    }

}
