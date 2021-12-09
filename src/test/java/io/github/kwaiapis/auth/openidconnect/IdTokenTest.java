package io.github.kwaiapis.auth.openidconnect;

import java.util.Collections;

import org.junit.jupiter.api.Test;

/**
 * @author yaolei03 <yaolei03@kuaishou.com>
 * Created on 2021-12-03
 */
public class IdTokenTest {

    @Test
    public void test1() throws Exception {
        String url = "http://localhost:8080/openapi/certs";
        IdTokenVerifier verifier = new IdTokenVerifier.Builder(new UrlJwkManager(url))
                .setAudience(Collections.singleton("clientId"))
                .build();

        String idTokenString =
                "eyJraWQiOiIzNGI0MzVlYy1hY2UzLTQ5ODAtOWE0Ny1hNjM0YTU3NDAyNjAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
                        + ".eyJub25jZSI6Im5vbmNlIiwiaXNzIjoiaHR0cHM6Ly93d3cua3dhaS1wcm8uY29tIiwic3ViIjoiMTIzIiwiYXVk"
                        + "IjoiY2xpZW50SWQiLCJleHAiOjE2Mzg4ODMwMDgsImlhdCI6MTYzODg3OTQwOCwiYXV0aF90aW1lIjpudWxsLCJ"
                        + "hY3IiOm51bGwsImFtciI6bnVsbCwiYXpwIjoiY2xpZW50SWQiLCJhdF9oYXNoIjpudWxsLCJuaWNrbmFtZSI6Im5p"
                        + "Y2tOYW1lIiwicGljdHVyZSI6InBpY3R1cmUiLCJwaG9uZV9udW1iZXIiOiJwaG9uZU51bWJlciIsInBob25lX251bW"
                        + "Jlcl92ZXJpZmllZCI6bnVsbCwibG9jYWxlIjpudWxsfQ.ReodLNivK-H8pU1nvsFMyE9vWYcImOJRKYDQvplyWdYWOq"
                        + "Fw6I01wnZsOzKqYD_SzgLfk6mE0f9E5HNBoT2qLqJPBVsEhMhP2XWy9oCHnPgEMPGYcMEm8cXKu69bqWWjt0sJEQHqI"
                        + "P00F1Tls6MCPvTKOTSMWWc6ljId1rQrksuC9x33m7-k6haapSlk_vfHnDRht_jjvPD184QtmkdoQfX9bXIGOgTutH3J"
                        + "1jvvdbwDTV-w5VyUUWPxvK5vqDejumDtGX4FOlYRC8DjLChBByyjEExQ8sgbI9qi3c1ByULPGOPKh3jOuRDMquZwRMgr"
                        + "GtfXpFXjQ6AaXjYnj8KRIg";
        IdToken idToken = verifier.verify(idTokenString);
        System.out.println(idToken != null);
    }
}
