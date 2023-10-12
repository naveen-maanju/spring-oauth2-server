package org.d3softtech.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.d3softtech.oauth2.server.exception.D3Exception;
import org.d3softtech.oauth2.server.userdetails.D3UserDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class D3UserDetailsService implements UserDetailsService {

    private final WebClient webClient;

    public D3UserDetailsService(@Value("${user.details.service.base.url}") String userServiceBaseUrl) {
        webClient = WebClient.builder().baseUrl(userServiceBaseUrl).build();

    }

    public UserDetails loadUserByUsername(String username) {
        D3User user = webClient.get()
            .uri(uriBuilder -> uriBuilder.path("/users").path("/username/{username}").build(username))
            .headers(httpHeaders -> httpHeaders.setBearerAuth(getToken())).retrieve()
            .onStatus(httpStatusCode -> httpStatusCode.isSameCodeAs(HttpStatus.NOT_FOUND),
                clientResponse -> Mono.error(new D3Exception("Bad credentials")))
            .bodyToMono(D3User.class).block(
                Duration.ofSeconds(2));

        return new D3UserDetails(user.userId, user.username, user.password, getAuthorities(user.roles), user.operatorId,
            user.isPasswordChangeRequired, user.roles);
    }

    private String getToken() {

        WebClient webClient = WebClient.builder().baseUrl("http://localhost:6060").build();
        Token token = webClient.post()
            .uri(uriBuilder -> uriBuilder.path("/oauth2/token").queryParam("grant_type", "client_credentials")
                .queryParam("username", "test-service").queryParam("roles", Set.of("service")).build())
            .headers(httpHeaders -> httpHeaders.setBasicAuth("spring-test", "test-secret")).retrieve()
            .bodyToMono(Token.class)
            .block(Duration.ofSeconds(2));

        assert token != null;
        return token.accessToken;
    }

    private List<GrantedAuthority> getAuthorities(Set<String> roles) {
        List<GrantedAuthority> authorities = new ArrayList<>(roles.size());
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        return authorities;
    }

    private record D3User(@JsonProperty("id") Integer userId, @JsonProperty("userName") String username,
                          String password, Set<String> roles, Short operatorId, boolean isPasswordChangeRequired) {

    }

    private record Token(@JsonProperty("access_token") String accessToken) {

    }
}
