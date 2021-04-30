package org.graylog.security.authservice.backend;

import com.github.joschi.jadconfig.Parameter;
import com.github.joschi.jadconfig.ValidationException;
import com.github.joschi.jadconfig.ValidatorMethod;
import com.github.joschi.jadconfig.util.Duration;
import com.github.joschi.jadconfig.validators.PositiveDurationValidator;
import com.github.joschi.jadconfig.validators.StringNotBlankValidator;
import com.github.joschi.jadconfig.validators.URIAbsoluteValidator;
import org.apache.commons.lang3.StringUtils;
import org.graylog2.plugin.PluginConfigBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

public class AuthConfiguration implements PluginConfigBean {
    private static final Logger log = LoggerFactory.getLogger(AuthConfiguration.class);

    private static final String PREFIX = "cloud_auth_";
    private static final String OAUTH_2_DEFAULT_PATH = "/oauth2/default";

    // For example: https://my-org.okta.com
    @Parameter(value = PREFIX + "okta_org_url", required = true, validators = URIAbsoluteValidator.class)
    private URI oktaOrgUrl;

    @Parameter(value = PREFIX + "okta_auth_server_path", validators = {StringNotBlankValidator.class})
    private String oktaAuthServerPath = OAUTH_2_DEFAULT_PATH;

    @Parameter(value = PREFIX + "callback_url", required = true, validators = {URIAbsoluteValidator.class})
    private URI callbackUrl;

    @Parameter(value = PREFIX + "client_id", required = true, validators = {StringNotBlankValidator.class})
    private String clientId;

    @Parameter(value = PREFIX + "client_secret", required = true, validators = {StringNotBlankValidator.class})
    private String clientSecret;

    @Parameter(value = PREFIX + "token_verifier_connection_timeout", validators = {PositiveDurationValidator.class})
    private Duration tokenVerifierConnectionTimeout = Duration.seconds(1);

    @Parameter(value = PREFIX + "okta_api_username", required = true, validators = StringNotBlankValidator.class)
    private String oktaApiUsername;

    @Parameter(value = PREFIX + "okta_api_password", required = true, validators = StringNotBlankValidator.class)
    private String oktaApiPassword;

    // The ID of the Okta user group to create the user within
    @Parameter(value = PREFIX + "okta_default_user_group_id", required = true, validators = StringNotBlankValidator.class)
    private String oktaDefaultUserGroupId;

    public URI getOktaBaseUrl() {
        try {
            return composeOktaBaseURI();
        } catch (URISyntaxException e) {
            // Should be an impossible exception, since a validator method checks this.
            throw new RuntimeException("Could not compose Okta base URL. Check that valid cloud_auth_okta_org_url and " +
                                       "cloud_auth_okta_auth_server_path (optional) values are provided.");
        }
    }

    public URI getCallbackUrl() {
        return callbackUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Duration getTokenVerifierConnectionTimeout() {
        return tokenVerifierConnectionTimeout;
    }

    public URI getOktaOrgUrl() {
        return oktaOrgUrl;
    }

    public String getOktaApiUsername() {
        return oktaApiUsername;
    }

    public String getOktaApiPassword() {
        return oktaApiPassword;
    }

    public String getOktaDefaultUserGroupId() {
        return oktaDefaultUserGroupId;
    }

    @ValidatorMethod
    @SuppressWarnings("unused")
    public void validateOktaOrgUrl() throws ValidationException {

        // Validate that a valid URL is supplied which meets the expectations of the Okta API.
        final String baseError = "Invalid " + PREFIX + "okta_org_url value. ";
        final String advice = " Must be in the hostname form with protocol. e.g. https://my-organization.okta.com";
        if (StringUtils.isNotBlank(oktaOrgUrl.getPath())) {
            throw new ValidationException(baseError + "The URL cannot contain a path or any slashes after the " +
                                          "hostname." + advice);
        }
        if (!oktaOrgUrl.getScheme().equals("https")) {
            throw new ValidationException(baseError + "The URL must use the https protocol." + advice);
        }
        if (oktaOrgUrl.getPort() != -1) {
            throw new ValidationException(baseError + "Custom ports are not supported." + advice);
        }
    }

    @ValidatorMethod
    @SuppressWarnings("unused")
    public void validateOktaAuthServerPath() throws ValidationException {

        // Check format of path. It should appear to be a path.
        // eg. /some/path is acceptable. http://some/path is not acceptable.
        if (!oktaAuthServerPath.startsWith("/")) {
            throw new ValidationException(String.format(Locale.ENGLISH, "Invalid cloud_auth_okta_auth_server_path value [%s]. " +
                                                        "Value must start with a forward slash eg. /oauth2/default",
                                                        oktaAuthServerPath));
        }

        // Verify that composition of the URL is successful.
        try {
            composeOktaBaseURI();
        } catch (URISyntaxException e) {
            throw new ValidationException(String.format(Locale.ENGLISH, "Failed to compose Okta base URL. orgUrl: %s authServerPath: %s",
                                                        oktaOrgUrl.toString(), oktaAuthServerPath), e);
        }
    }

    private URI composeOktaBaseURI() throws URISyntaxException {
        return new URI(oktaOrgUrl.toString() + oktaAuthServerPath);
    }
}
