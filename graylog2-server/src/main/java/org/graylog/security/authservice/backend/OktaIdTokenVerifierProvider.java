package org.graylog.security.authservice.backend;

import com.google.inject.Inject;
import com.okta.jwt.IdTokenVerifier;
import com.okta.jwt.JwtVerifiers;

import javax.inject.Provider;
import java.time.Duration;

public class OktaIdTokenVerifierProvider implements Provider<IdTokenVerifier> {
    private final AuthConfiguration configuration;

    @Inject
    public OktaIdTokenVerifierProvider(AuthConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public IdTokenVerifier get() {
        // JwtVerifiers uses java.util.ServiceLoader.load(java.lang.Class<S>) to load its implementation. This
        // will use the thread context class loader, which in our case is wrong as it is unable to find resources
        // in the plugin classpath and therefore loading the implementation would fail. We'll work around this
        // by temporarily setting the thread context class loader to the plugin class loader.
        // See https://stackoverflow.com/a/36228195
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            return create();
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    private IdTokenVerifier create() {
        return JwtVerifiers.idTokenVerifierBuilder()
                .setIssuer(configuration.getOktaBaseUrl().toString())
                .setClientId(configuration.getClientId())
                .setConnectionTimeout(Duration.ofMillis(configuration.getTokenVerifierConnectionTimeout()
                        .toMilliseconds()))
                .build();
    }
}
