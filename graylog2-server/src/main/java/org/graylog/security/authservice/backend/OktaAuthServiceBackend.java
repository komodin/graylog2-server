package org.graylog.security.authservice.backend;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.value.AutoValue;
import com.google.inject.assistedinject.Assisted;
import com.okta.jwt.IdTokenVerifier;
import com.okta.jwt.JwtVerificationException;
import com.unboundid.util.Base64;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.graylog.security.authservice.AuthServiceBackend;
import org.graylog.security.authservice.AuthServiceBackendDTO;
import org.graylog.security.authservice.AuthServiceCredentials;
import org.graylog.security.authservice.AuthServiceToken;
import org.graylog.security.authservice.AuthenticationDetails;
import org.graylog.security.authservice.ProvisionerService;
import org.graylog.security.authservice.UserDetails;
import org.graylog.security.authservice.test.AuthServiceBackendTestResult;
import org.graylog2.database.NotFoundException;
import org.graylog2.security.encryption.EncryptedValueService;
import org.graylog2.shared.security.AuthenticationServiceUnavailableException;
import org.graylog2.users.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Authenticate a user based on an Okta OIDC authorization code which is exchanged for an id token
 */
public class OktaAuthServiceBackend implements AuthServiceBackend {
    public static final String TYPE_NAME = "okta";
    public static final String TITLE = "Okta";
    public static final String ID = "Okta";

    public static final String HANDLED_TOKEN_TYPE = "authorization-code";
    public static final String ID_TOKEN_SESSION_KEY = "id-token";

    private static final Logger log = LoggerFactory.getLogger(OktaAuthServiceBackend.class);

    public interface Factory extends AuthServiceBackend.Factory<OktaAuthServiceBackend> {
        @Override
        OktaAuthServiceBackend create(AuthServiceBackendDTO backend);
    }

    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final IdTokenVerifier idTokenVerifier;
    private final RoleService roleService;
    private final EncryptedValueService encryptedValueService;
    private final OktaAuthServiceBackendConfig config;

    @Inject
    public OktaAuthServiceBackend(OkHttpClient httpClient, ObjectMapper objectMapper, IdTokenVerifier idTokenVerifier,
                                  RoleService roleService, EncryptedValueService encryptedValueService,
                                  @Assisted AuthServiceBackendDTO backend) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.idTokenVerifier = idTokenVerifier;
        this.roleService = roleService;
        this.encryptedValueService = encryptedValueService;
        this.config = (OktaAuthServiceBackendConfig) backend.config();
    }

    @Override
    public Optional<AuthenticationDetails> authenticateAndProvision(AuthServiceToken token,
            ProvisionerService provisionerService) {

        if (!token.type().equals(HANDLED_TOKEN_TYPE)) {
            log.warn("Unable to handle token of type <{}>.", token.type());
            return Optional.empty();
        }

        OidcTokens tokens = fetchTokensFromAuthServer(token.token());
        if (tokens == null || !areTokensValid(tokens)) {
            return Optional.empty();
        }

        OktaUserinfo userinfo = fetchUserinfoFromAuthServer(tokens.accessToken());
        if (userinfo == null) {
            return Optional.empty();
        }

        final String firstName = userinfo.givenName().orElseThrow(
                () -> new IllegalArgumentException("Cannot provision user. A given_name (first name) is required."));
        final String lastName = userinfo.familyName().orElseThrow(
                () -> new IllegalArgumentException("Cannot provision user. A family_name (last name) is required."));

        try {

            final UserDetails userDetails = provisionerService.provision(provisionerService.newDetails(this)
                    .authServiceType(backendType())
                    .authServiceId(backendId())
                    .accountIsEnabled(true)
                    .base64AuthServiceUid(Base64.encode(userinfo.sub()))
                    .username(userinfo.preferredUsername())
                    .firstName(firstName)
                    .lastName(lastName)
                    .email(userinfo.email())
                    .isExternal(false) // Okta records are editable.
                    .defaultRoles(getRoleIds(userinfo.preferredUsername(), userinfo.initialGraylogRoles()))
                    .build());
            final AuthenticationDetails authDetails = AuthenticationDetails.builder()
                    .userDetails(userDetails)
                    .sessionAttributes(Collections.singletonMap(ID_TOKEN_SESSION_KEY, tokens.idToken()))
                    .build();
            return Optional.of(authDetails);
        } catch (Exception e) {
            log.error("Unable to provision user. Provisioner failed with error:", e);
            throw new AuthenticationServiceUnavailableException(e);
        }
    }

    @Override
    public String backendType() {
        return TYPE_NAME;
    }

    @Override
    public String backendId() {
        return ID;
    }

    @Override
    public String backendTitle() {
        return TITLE;
    }

    @Override
    public AuthServiceBackendDTO prepareConfigUpdate(AuthServiceBackendDTO existingBackend,
            AuthServiceBackendDTO newBackend) {
        return newBackend;
    }

    @Override
    public AuthServiceBackendTestResult testConnection(@Nullable AuthServiceBackendDTO existingBackendConfig) {
        return AuthServiceBackendTestResult.createFailure("Not implemented");
    }

    @Override
    public AuthServiceBackendTestResult testLogin(AuthServiceCredentials credentials,
            @Nullable AuthServiceBackendDTO existingConfig) {
        return AuthServiceBackendTestResult.createFailure("Not implemented");
    }

    // TODO: do we need to check anything at all? After all these come directly from okta.
    //  If we need to check, do we have to check that the access token matches some claims in the id token?
    private boolean areTokensValid(OidcTokens tokens) {
        // Verify the claims in the token and check the signature
        try {
            idTokenVerifier.decode(tokens.idToken(), null);
        } catch (JwtVerificationException e) {
            log.error("Unable to verify OIDC id token.", e);
            return false;
        }

        return true;
    }

    private OidcTokens fetchTokensFromAuthServer(String authCode) {
        FormBody requestBody = new FormBody.Builder()
                .add("grant_type", "authorization_code")
                .add("redirect_uri", config.callbackUrl())
                .add("code", authCode)
                .build();
        Request request = new Request.Builder()
                .url(config.oktaBaseUrl() + "/v1/token")
                .header("Authorization", getBasicAuthHeaderValue())
                .header("accept", "application/json")
                .post(requestBody)
                .build();

        final String tokenJson = callAuthServer(request);

        if (tokenJson == null) {
            return null;
        }

        try {
            JsonNode jsonNode = objectMapper.readTree(tokenJson);
            String accessToken = jsonNode.get("access_token").asText();
            String idToken = jsonNode.get("id_token").asText();
            return OidcTokens.create(accessToken, idToken);
        } catch (Exception e) {
            log.error("Unable to parse JSON response and extract id and access tokens from token json: '" +
                    tokenJson + "'.", e);
            return null;
        }
    }

    private OktaUserinfo fetchUserinfoFromAuthServer(String accessToken) {
        Request request = new Request.Builder()
                .header("Authorization", "Bearer " + accessToken)
                .url(config.oktaBaseUrl() + "/v1/userinfo")
                .get()
                .build();
        String json = callAuthServer(request);

        if (json != null) {
            try {
                return objectMapper.readValue(json, OktaUserinfo.class);
            } catch (IOException e) {
                log.error("Unable to extract userinfo from userinfo json response '" + json + "'. Have all required " +
                        "scopes (openid, profile, email) been requested in the initial \"authorization\" request?", e);
            }
        }

        return null;
    }

    private String callAuthServer(Request request) {
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";

            if (response.isSuccessful() && StringUtils.isNotBlank(body)) {
                log.debug("OIDC auth server responded with {} {}; body: {}", response.code(), response.message(), body);
                return body;
            } else {
                log.error("Unable to fetch data from OIDC auth server. Got: {} {}; body: {}", response.code(),
                        response.message(), body);
            }
        } catch (Exception e) {
            log.error("Encountered an error when attempting to fetch data from the OIDC auth server.", e);
            throw new AuthenticationServiceUnavailableException(e);
        }
        return null;
    }

    private String getBasicAuthHeaderValue() {
        String credentials = config.clientId() + ":" + encryptedValueService.decrypt(config.clientSecret());
        return "Basic " + Base64.encode(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Get IDs for initial roles by translating the role names from the Okta user profile. Roles which are unknown will
     * be skipped.
     */
    private Set<String> getRoleIds(String username, Set<String> initialRolesFromOkta) {
        Set<String> roleIds = new HashSet<>();
        for (String name : initialRolesFromOkta) {
            try {
                roleIds.add(roleService.load(name).getId());
                log.debug("Added default role <{}> for user <{}>", name, username);
            } catch (NotFoundException e) {
                log.warn("Unknown initial role <{}> set in Okta for provisioning user <{}>. Ignoring role.", name,
                        username);
            }
        }

        if (roleIds.isEmpty()) {
            log.debug("Adding default role <Reader> for user because no valid initial roles configured in Okta");
            roleIds.add(roleService.getReaderRoleObjectId());
        }

        return roleIds;
    }

    @AutoValue
    static abstract class OidcTokens {
        abstract String accessToken();

        abstract String idToken();

        public static OidcTokens create(String accessToken, String idToken) {
            return new AutoValue_OktaAuthServiceBackend_OidcTokens(accessToken, idToken);
        }
    }
}
