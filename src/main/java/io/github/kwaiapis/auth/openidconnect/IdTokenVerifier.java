package io.github.kwaiapis.auth.openidconnect;

import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;


/**
 * @author yaolei03
 * @since 2021-12-01
 */
public class IdTokenVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(IdTokenVerifier.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    /**
     * Default value for seconds of time skew to accept when verifying time (5 minutes).
     */
    public static final long DEFAULT_TIME_SKEW_SECONDS = 300;

    private final UrlJwkManager urlJwkManager;

    private final long acceptableTimeSkewSeconds;

    private final String issuer;

    private final Collection<String> audience;

    protected IdTokenVerifier(IdTokenVerifier.Builder builder) {
        this.urlJwkManager = builder.publicKeys;
        this.acceptableTimeSkewSeconds = builder.acceptableTimeSkewSeconds;
        this.issuer = builder.issuer;
        this.audience = builder.audience;
    }

    public IdToken verify(String idTokenString) {
        try {
            SignedJWT jwt = SignedJWT.parse(idTokenString);
            if (jwt == null) {
                LOG.info("parse fail. {}", idTokenString);
                return null;
            }
            String kid = jwt.getHeader().getKeyID();
            if (kid == null) {
                LOG.info("invalid header. {}", idTokenString);
                return null;
            }
            RSAKey rsaKey = urlJwkManager.getPublicKey(kid);
            if (rsaKey == null) {
                LOG.info("invalid kid. {}", idTokenString);
                return null;
            }
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            boolean verified = jwt.verify(verifier);
            if (!verified) {
                LOG.info("invalid sig. {}", idTokenString);
                return null;
            }
            IdToken token = convert(jwt);
            verified = verifyIdToken(token);
            if (!verified) {
                LOG.info("invalid state. {}", idTokenString);
                return null;
            }
            return token;
        } catch (Exception e) {
            LOG.error("validate id token fail. {}", idTokenString, e);
        }
        return null;
    }

    private boolean verifyIdToken(IdToken idToken) {
        return idToken.verifyIssuer(issuer) && idToken.verifyAudience(audience)
                && idToken.verifyTime(System.currentTimeMillis(), acceptableTimeSkewSeconds);
    }

    private IdToken convert(SignedJWT jwt) throws Exception {
        IdToken.Header header = new IdToken.Header();
        header.setAlgorithm(jwt.getHeader().getAlgorithm().getName());
        header.setType(jwt.getHeader().getType().getType());
        header.setKeyId(jwt.getHeader().getKeyID());

        IdToken.Payload payload = MAPPER.readValue(jwt.getPayload().toString(), IdToken.Payload.class);
        return new IdToken(header, payload);
    }

    public static class Builder {
        UrlJwkManager publicKeys;

        long acceptableTimeSkewSeconds = DEFAULT_TIME_SKEW_SECONDS;

        String issuer;

        Collection<String> audience;

        public Builder(UrlJwkManager publicKeys) {
            this.publicKeys = Preconditions.checkNotNull(publicKeys);
            setIssuer("https://www.kwai-pro.com");
        }

        public Builder setAcceptableTimeSkewSeconds(long acceptableTimeSkewSeconds) {
            Preconditions.checkArgument(acceptableTimeSkewSeconds >= 0);
            this.acceptableTimeSkewSeconds = acceptableTimeSkewSeconds;
            return this;
        }

        public Builder setIssuer(String issuer) {
            Preconditions.checkArgument(StringUtils.isNotBlank(issuer), "Issuer must not be empty");
            this.issuer = issuer;
            return this;
        }

        public Builder setAudience(Collection<String> audience) {
            this.audience = audience;
            return this;
        }

        public IdTokenVerifier build() {
            Preconditions.checkArgument(issuer != null && audience != null, "invalid param");
            return new IdTokenVerifier(this);
        }
    }
}
