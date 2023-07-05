# oauth2-authorization-server

### Docs:
[Authorization Code Flow](docs/authorization_code_flow.md) `docs/authorization_code_flow.md`
<br/>
[Authorization Code Flow with PKCE](docs/authorization_code_flow_with_pkce.md) `docs/authorization_code_flow_with_pkce.md`

###  References:
[Implement core service with JPA](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-jpa.html#client-schema)

### Supported features:
- [x] Authorization Code Flow
- [x] Authorization Code Flow with PKCE
- [x] Token Introspection
- [x] Token Revocation
- [x] Custom UserDetails
- [x] Custom login page
- [x] OAuth2 Login
- [x] Allow maximum 2 sessions per user (Can change in the DefaultSecurityConfig)
- [x] Logout
- [x] Logout from all sessions
- [x] Integrated with JPA to store client details (Registered Client, Authorization, AuthorizationConsent, User, and
    Role)
- [x] Custom MFA page
- [x] MFA using TOTP (Worked fine with Google Authenticator)