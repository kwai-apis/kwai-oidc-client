package io.github.kwaiapis.auth.openidconnect;

import java.util.Collection;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author yaolei03
 * @since 2021-12-01
 */
public class IdToken {

    private Header header;

    private Payload payload;

    public IdToken(Header header, Payload payload) {
        this.header = header;
        this.payload = payload;
    }

    public Header getHeader() {
        return header;
    }

    public Payload getPayload() {
        return payload;
    }

    public static class Header {

        @JsonProperty("type")
        private String type;

        @JsonProperty("alg")
        private String algorithm;

        @JsonProperty("kid")
        private String keyId;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }
    }

    public static class Payload {
        /**
         * required
         */
        @JsonProperty("iss")
        private String issuer;

        /**
         * required
         */
        @JsonProperty("sub")
        private String subject;

        /**
         * required
         */
        @JsonProperty("aud")
        private String audience;

        /**
         * required
         */
        @JsonProperty("exp")
        private Long expirationTimeSeconds;

        /**
         * required
         */
        @JsonProperty("iat")
        private Long issuedAtTimeSeconds;

        /**
         * optional
         */
        @JsonProperty("auth_time")
        private Long authorizationTimeSeconds;

        /**
         * Value used to associate a client session with an ID token or {@code null} for none.
         */
        @JsonProperty
        private String nonce;

        /**
         * Authentication context class reference or {@code null} for none.
         */
        @JsonProperty("acr")
        private String classReference;

        /**
         * Authentication methods references or {@code null} for none.
         */
        @JsonProperty("amr")
        private List<String> methodsReferences;

        /**
         * Authorized party or {@code null} for none.
         */
        @JsonProperty("azp")
        private String authorizedParty;

        /**
         * Access token hash value or {@code null} for none.
         */
        @JsonProperty("at_hash")
        private String accessTokenHash;

        // --Standard Claims--

        @JsonProperty("nickname")
        private String nickname;

        @JsonProperty("picture")
        private String picture;

        @JsonProperty("phone_number")
        private String phoneNumber;

        @JsonProperty("phone_number_verified")
        private Boolean phoneNumberVerified;

        @JsonProperty("locale")
        private String locale;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public Long getExpirationTimeSeconds() {
            return expirationTimeSeconds;
        }

        public void setExpirationTimeSeconds(Long expirationTimeSeconds) {
            this.expirationTimeSeconds = expirationTimeSeconds;
        }

        public Long getIssuedAtTimeSeconds() {
            return issuedAtTimeSeconds;
        }

        public void setIssuedAtTimeSeconds(Long issuedAtTimeSeconds) {
            this.issuedAtTimeSeconds = issuedAtTimeSeconds;
        }

        public Long getAuthorizationTimeSeconds() {
            return authorizationTimeSeconds;
        }

        public void setAuthorizationTimeSeconds(Long authorizationTimeSeconds) {
            this.authorizationTimeSeconds = authorizationTimeSeconds;
        }

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getClassReference() {
            return classReference;
        }

        public void setClassReference(String classReference) {
            this.classReference = classReference;
        }

        public List<String> getMethodsReferences() {
            return methodsReferences;
        }

        public void setMethodsReferences(List<String> methodsReferences) {
            this.methodsReferences = methodsReferences;
        }

        public String getAuthorizedParty() {
            return authorizedParty;
        }

        public void setAuthorizedParty(String authorizedParty) {
            this.authorizedParty = authorizedParty;
        }

        public String getAccessTokenHash() {
            return accessTokenHash;
        }

        public void setAccessTokenHash(String accessTokenHash) {
            this.accessTokenHash = accessTokenHash;
        }

        public String getNickname() {
            return nickname;
        }

        public void setNickname(String nickname) {
            this.nickname = nickname;
        }

        public String getPicture() {
            return picture;
        }

        public void setPicture(String picture) {
            this.picture = picture;
        }

        public String getPhoneNumber() {
            return phoneNumber;
        }

        public void setPhoneNumber(String phoneNumber) {
            this.phoneNumber = phoneNumber;
        }

        public Boolean getPhoneNumberVerified() {
            return phoneNumberVerified;
        }

        public void setPhoneNumberVerified(Boolean phoneNumberVerified) {
            this.phoneNumberVerified = phoneNumberVerified;
        }

        public String getLocale() {
            return locale;
        }

        public void setLocale(String locale) {
            this.locale = locale;
        }
    }

    public final boolean verifyIssuer(String expectedIssuer) {
        return expectedIssuer.equals(getPayload().getIssuer());
    }

    public final boolean verifyAudience(Collection<String> trustedClientIds) {
        return trustedClientIds.contains(getPayload().getAudience());
    }

    public final boolean verifyTime(long currentTimeMillis, long acceptableTimeSkewSeconds) {
        return verifyExpirationTime(currentTimeMillis, acceptableTimeSkewSeconds)
                && verifyIssuedAtTime(currentTimeMillis, acceptableTimeSkewSeconds);
    }

    public final boolean verifyExpirationTime(
            long currentTimeMillis, long acceptableTimeSkewSeconds) {
        return (currentTimeMillis / 1000)
                <= (getPayload().getExpirationTimeSeconds() + acceptableTimeSkewSeconds);
    }

    public final boolean verifyIssuedAtTime(long currentTimeMillis, long acceptableTimeSkewSeconds) {
        return (currentTimeMillis / 1000)
                >= (getPayload().getIssuedAtTimeSeconds() - acceptableTimeSkewSeconds);
    }
}
