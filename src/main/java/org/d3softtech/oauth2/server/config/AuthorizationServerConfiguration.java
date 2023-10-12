package org.d3softtech.oauth2.server.config;

import org.d3softtech.oauth2.server.jwt.customizer.OAuth2TokenCustomizerDelegate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;


@Configuration
public class AuthorizationServerConfiguration {

    @Bean
    protected OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return new OAuth2TokenCustomizerDelegate();
    }


}
