package org.d3softtech.oauth2.server.response;

public record JWKSResponse(JWKSEntry[] jwksEntries) {

  public record JWKSEntry(String kid, String n, String kty, String e){

  }
}
