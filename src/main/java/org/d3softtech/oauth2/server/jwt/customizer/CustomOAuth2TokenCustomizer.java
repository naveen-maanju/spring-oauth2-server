package org.d3softtech.oauth2.server.jwt.customizer;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public interface CustomOAuth2TokenCustomizer extends OAuth2TokenCustomizer<JwtEncodingContext> {

    boolean isTokenSupported(JwtEncodingContext jwtContext);
}
