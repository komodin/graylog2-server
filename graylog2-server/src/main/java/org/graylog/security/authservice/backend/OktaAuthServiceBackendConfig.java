package org.graylog.security.authservice.backend;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.security.authservice.AuthServiceBackendConfig;
import org.graylog2.security.encryption.EncryptedValue;

import java.time.Duration;

@AutoValue
@JsonDeserialize(builder = OktaAuthServiceBackendConfig.Builder.class)
@JsonTypeName(OktaAuthServiceBackend.TYPE_NAME)
public abstract class OktaAuthServiceBackendConfig implements AuthServiceBackendConfig {
    private static final String FIELD_OKTA_BASE_URL = "okta_base_url";
    private static final String FIELD_CALLBACK_URL = "callback_url";
    private static final String FIELD_CLIENT_ID = "client_id";
    private static final String FIELD_CLIENT_SECRET = "client_secret";
    private static final String FIELD_TOKEN_VERIFIER_CONNECT_TIMEOUT = "token_verifier_connect_timeout";

    public static Builder builder() {
        return Builder.create();
    }

    @JsonProperty(FIELD_OKTA_BASE_URL)
    public abstract String oktaBaseUrl();

    @JsonProperty(FIELD_CALLBACK_URL)
    public abstract String callbackUrl();

    @JsonProperty(FIELD_CLIENT_ID)
    public abstract String clientId();

    @JsonProperty(FIELD_CLIENT_SECRET)
    public abstract EncryptedValue clientSecret();

    @JsonProperty(FIELD_TOKEN_VERIFIER_CONNECT_TIMEOUT)
    public abstract Duration tokenVerifierConnectTimeout();

    @AutoValue.Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public abstract static class Builder implements AuthServiceBackendConfig.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_OktaAuthServiceBackendConfig.Builder().type(OktaAuthServiceBackend.TYPE_NAME);
        }

        @JsonProperty(FIELD_OKTA_BASE_URL)
        public abstract Builder oktaBaseUrl(String oktaBaseUrl);

        @JsonProperty(FIELD_CALLBACK_URL)
        public abstract Builder callbackUrl(String callbackUrl);

        @JsonProperty(FIELD_CLIENT_ID)
        public abstract Builder clientId(String clientId);

        @JsonProperty(FIELD_CLIENT_SECRET)
        public abstract Builder clientSecret(EncryptedValue clientSecret);

        @JsonProperty(FIELD_TOKEN_VERIFIER_CONNECT_TIMEOUT)
        public abstract Builder tokenVerifierConnectTimeout(Duration tokenVerifierConnectTimeout);

        public abstract OktaAuthServiceBackendConfig build();
    }
}
