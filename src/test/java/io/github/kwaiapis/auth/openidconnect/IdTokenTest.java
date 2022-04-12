package io.github.kwaiapis.auth.openidconnect;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author yaolei03 <yaolei03@kuaishou.com>
 * Created on 2021-12-03
 */
public class IdTokenTest {

    @Test
    public void test1() throws Exception {
        IdTokenVerifier verifier = new IdTokenVerifier.Builder(new UrlJwkManager())
                .setAudience(Collections.singleton("clientId"))
                .build();

        String idTokenString =
                "eyJraWQiOiIzNGI0MzVlYy1hY2UzLTQ5ODAtOWE0Ny1hNjM0YTU3NDAyNjAiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
                        + ".eyJub25jZSI6Im5vbmNlIiwiaXNzIjoiaHR0cHM6Ly93d3cua3dhaS5jb20iLCJzdWIiOiIxMjMiLCJhdWQiOiJ"
                        + "jbGllbnRJZCIsImV4cCI6MTY0NjEyNzIzMCwiaWF0IjoxNjQ2MTIzNjMwLCJhenAiOiJjbGllbnRJZCIsIm5pY2t"
                        + "uYW1lIjoibmlja05hbWUiLCJwaWN0dXJlIjoicGljdHVyZSIsInBob25lX251bWJlciI6InBob25lTnVtYmVyIn0."
                        + "n8JWCTSsd5BbhhNbJYyoFc0WcrudU-aTm54kn-YeF2f49g0nMkblTma9rrkcqd5J8z3Q0f2WRPVJnutK533eXy9jh"
                        + "lLB2bWAskW8H78zvBsqdMCOKWgUsoqL_4TyO4RBjj4Gf1415YO24Hj_eS17LBoklA7hEmwoTCk6Bm7L3XHTVwUioSB"
                        + "nOXTi8O1E_IWIsNw_5KENfTwomOj16vXXrdoI6JZSwQR-46-pRAYcajb05CfKe7klqG7iY8UhDJtRV1vkBtKuwtTd3k"
                        + "6S_H6-_HHCUj1vFH9px_mcpiVwWwpVANoTo3Fxj5FYA1qIvF4t17WEl5BuF1CdvcaVgnx_hw";
        IdToken idToken = verifier.verify(idTokenString);
        Assertions.assertTrue(idToken != null);
    }

    @Test
    public void test2() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JavaType javaType = mapper.getTypeFactory().constructMapType(HashMap.class, String.class, String.class);

        String json = "{\"event\":\"REVOKE\",\"time\":1649757612,"
                + "\"sign\":\"hFWlXaJtoV7MgOk3xIUbz1PHJ5+z1+/B1v04fZBB0qVjKntWcU3dV+M2CxE7BAPzPQS5YgQi7uMBr74"
                + "+PVJRes5N6D5tN7aDCsRh7XCWT2dxGNAvqsc9WeMG3vH1+tVbNjda"
                + "/UF3D1TCaDmOkTDNRcSNH78YvbXz2kOcCLHJq0WONxUGEfjdUM5oiVG8QJ3dysIWzGhWJU3jV0uwNzo"
                + "/tiA4X1Oga2fehhbWyH9fUPo9eFW43GzmlYQSK7CteQH0lPTOXPNwaeXQFBbi"
                + "/fSOo8WGObFhTwKU82PYH7YkYO8RcJSyBBDF3Mqy2LWt3W9FlyLDKRWzqKFLIVqBZmrKVw==\","
                + "\"client_id\":\"test123\",\"open_id\":\"6c0b0bd511f4070370ac639545550764\","
                + "\"sign_type\":\"SHA256WithRSA\",\"sign_kid\":\"34b435ec-ace3-4980-9a47-a634a5740260\"}";
        Map<String, String> param = mapper.readValue(json, javaType);

        UrlJwkManager manager =
                new UrlJwkManager(new URL("https://app.kwai.com/openapi/certs"), 1000, 1000, null, null);

        boolean pass = SignatureVerifier.checkSign(param, manager);
        Assertions.assertTrue(pass);
    }
}
