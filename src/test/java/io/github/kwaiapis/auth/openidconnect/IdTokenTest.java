package io.github.kwaiapis.auth.openidconnect;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
}
