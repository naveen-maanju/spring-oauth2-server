# spring-oauth2-server
Authorization server for OAuth2

This is a default authorization server provided by Spring Security without any 

"{noop}secret"

### Well-known endpoint
GET http://localhost:6060/.well-known/oauth-authorization-server

### GET oauth2/token endpoint
GET http://localhost:6060/oauth2/jwks

### POST oauth2/token endpoint
POST http://localhost:6060/oauth2/token?grant_type=client_credentials
Authorization: Basic spring-test test-secret


Rotate keys