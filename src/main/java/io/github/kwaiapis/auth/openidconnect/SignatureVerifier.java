package io.github.kwaiapis.auth.openidconnect;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * @author yaolei03
 * Created on 2022-04-02
 */
public class SignatureVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureVerifier.class);

    public static boolean checkSign(Map<String, String> params, UrlJwkManager urlJwkManager) {
        if (MapUtils.isEmpty(params)) {
            return false;
        }

        String signKid = params.get("sign_kid");
        String sign = params.get("sign");
        String content = getSignContent(params);
        if (StringUtils.isBlank(signKid) || StringUtils.isBlank(sign) || StringUtils.isBlank(content)) {
            LOG.info("invalid params.");
            return false;
        }

        RSAKey rsaKey = urlJwkManager.getPublicKey(signKid);
        if (rsaKey == null) {
            LOG.info("invalid signKid. {}", signKid);
            return false;
        }
        PublicKey pubKey = null;
        try {
            pubKey = rsaKey.toPublicKey();
        } catch (JOSEException e) {
            LOG.info("invalid public key.");
            return false;
        }

        if (pubKey == null) {
            LOG.info("invalid public key.");
            return false;
        }

        return doCheckSign(content, pubKey, sign);
    }

    // ----

    private static boolean doCheckSign(String content, PublicKey pubKey, String sign) {
        try {
            Signature signature = Signature.getInstance(SIGN_SHA256RSA_ALGORITHMS);
            signature.initVerify(pubKey);
            signature.update(content.getBytes(StandardCharsets.UTF_8));

            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            LOG.info("verify sign fail.", e);
        }
        return false;
    }

    private static String getSignContent(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return null;
        }

        StringBuilder content = new StringBuilder();
        List<String> keys = new ArrayList<>(params.keySet());
        Collections.sort(keys);

        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            String value = params.get(key);

            if (key.startsWith("sign")) {
                continue;
            }

            content.append("&").append(key).append("=").append(value);
        }

        if (content.length() > 0) {
            // remove first &
            return content.substring(1);
        }
        return content.toString();
    }

    public static final String SIGN_SHA256RSA_ALGORITHMS = "SHA256WithRSA";
}
