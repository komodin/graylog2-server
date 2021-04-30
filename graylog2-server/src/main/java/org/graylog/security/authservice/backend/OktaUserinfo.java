package org.graylog.security.authservice.backend;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

/**
 * Bean class for the claims in the "email" and "profile" scope of a "/userinfo" response.
 * <p>
 * Only "sub", "name", "email" and "preferredUsername" are required to be not null.
 */
@AutoValue
@JsonDeserialize(builder = OktaUserinfo.Builder.class)
public abstract class OktaUserinfo {
    private static final String FAMILY_NAME = "family_name";
    private static final String GIVEN_NAME = "given_name";
    private static final String MIDDLE_NAME = "middle_name";
    private static final String PREFERRED_USERNAME = "preferred_username";
    private static final String UPDATED_AT = "updated_at";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String INITIAL_GRAYLOG_ROLES = "initial_graylog_roles";

    @JsonProperty
    public abstract String sub();

    @JsonProperty
    public abstract String name();

    @JsonProperty(FAMILY_NAME)
    public abstract Optional<String> familyName();

    @JsonProperty(GIVEN_NAME)
    public abstract Optional<String> givenName();

    @JsonProperty(MIDDLE_NAME)
    public abstract Optional<String> middleName();

    @JsonProperty
    public abstract Optional<String> nickname();

    @JsonProperty(PREFERRED_USERNAME)
    public abstract String preferredUsername();

    @JsonProperty
    public abstract Optional<String> profile();

    @JsonProperty
    public abstract Optional<String> picture();

    @JsonProperty
    public abstract Optional<String> website();

    @JsonProperty
    public abstract Optional<String> gender();

    @JsonProperty
    public abstract Optional<String> birthdate();

    @JsonProperty
    public abstract Optional<String> zoneinfo();

    @JsonProperty
    public abstract Optional<String> locale();

    @JsonProperty(UPDATED_AT)
    public abstract Optional<String> updatedAt();

    @JsonProperty
    public abstract String email();

    @JsonProperty(EMAIL_VERIFIED)
    public abstract Optional<Boolean> emailVerified();

    @JsonProperty(INITIAL_GRAYLOG_ROLES)
    public abstract Set<String> initialGraylogRoles();

    public static Builder builder() {
        return Builder.create();
    }

    @AutoValue.Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public abstract static class Builder {

        @JsonCreator
        public static Builder create() {
            return new AutoValue_OktaUserinfo.Builder()
                    .initialGraylogRoles(Collections.emptySet());
        }

        @JsonProperty
        public abstract Builder sub(String sub);

        @JsonProperty
        public abstract Builder name(String name);

        @JsonProperty(FAMILY_NAME)
        public abstract Builder familyName(@Nullable String familyName);

        @JsonProperty(GIVEN_NAME)
        public abstract Builder givenName(@Nullable String givenName);

        @JsonProperty(MIDDLE_NAME)
        public abstract Builder middleName(@Nullable String middleName);

        @JsonProperty
        public abstract Builder nickname(@Nullable String nickname);

        @JsonProperty(PREFERRED_USERNAME)
        public abstract Builder preferredUsername(String preferredUsername);

        @JsonProperty
        public abstract Builder profile(@Nullable String profile);

        @JsonProperty
        public abstract Builder picture(@Nullable String picture);

        @JsonProperty
        public abstract Builder website(@Nullable String website);

        @JsonProperty
        public abstract Builder gender(@Nullable String gender);

        @JsonProperty
        public abstract Builder birthdate(@Nullable String birthdate);

        @JsonProperty
        public abstract Builder zoneinfo(@Nullable String zoneinfo);

        @JsonProperty
        public abstract Builder locale(@Nullable String locale);

        @JsonProperty(UPDATED_AT)
        public abstract Builder updatedAt(@Nullable String updatedAt);

        @JsonProperty
        public abstract Builder email(String email);

        @JsonProperty(EMAIL_VERIFIED)
        public abstract Builder emailVerified(@Nullable Boolean emailVerified);

        @JsonProperty(INITIAL_GRAYLOG_ROLES)
        public abstract Builder initialGraylogRoles(Set<String> initialGraylogRoles);

        public abstract OktaUserinfo build();
    }
}
