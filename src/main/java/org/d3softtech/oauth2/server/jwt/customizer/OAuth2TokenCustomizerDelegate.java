package org.d3softtech.oauth2.server.jwt.customizer;

import java.util.List;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class OAuth2TokenCustomizerDelegate implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final List<CustomOAuth2TokenCustomizer> jwtTokenCustomizers;

    public OAuth2TokenCustomizerDelegate() {
        jwtTokenCustomizers = List.of(new OAuthClientTokenCustomizer(), new OAuth2AuthenticatedUserTokenCustomizer());
    }

    @Override
    public void customize(JwtEncodingContext context) {
        jwtTokenCustomizers.stream().filter(customizer -> customizer.isTokenSupported(context))
            .forEach(customizer -> customizer.customize(context));
    }
}
