package org.d3softtech.oauth2.server.config;

import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class AuthorizationServerConfiguration {


    @Bean
    protected OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return jwtContext -> {
            OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = jwtContext.getAuthorizationGrant();
            Map<String, Object> additionalParameters = clientCredentialsAuthentication.getAdditionalParameters();
            additionalParameters.forEach((key, value) -> jwtContext.getClaims().claim(key, value));
        };
    }
}
