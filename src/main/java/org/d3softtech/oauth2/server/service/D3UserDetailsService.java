package org.d3softtech.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lombok.Builder;
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
        .uri(uriBuilder -> uriBuilder.path("/users").path("/{username}").build(username))
        .retrieve()
        .onStatus(httpStatusCode -> httpStatusCode.isSameCodeAs(HttpStatus.NOT_FOUND),
            clientResponse -> Mono.error(new D3Exception("Bad credentials")))
        .bodyToMono(D3User.class).block(
            Duration.ofSeconds(2));

    return new D3UserDetails(user.userId(), user.username(), user.password(), getAuthorities(user.roles()), user.ssn(),
        user.email(), user.isPasswordChangeRequired(), user.roles());
  }


  private List<GrantedAuthority> getAuthorities(List<String> roles) {
    List<GrantedAuthority> authorities = new ArrayList<>(roles.size());
    for (String role : roles) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return authorities;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  @Builder
  public record D3User(@JsonProperty("id") Integer userId, @JsonProperty("userName") String username,
                       String password, List<String> roles, String ssn, String email,
                       boolean isPasswordChangeRequired) {

  }

}
