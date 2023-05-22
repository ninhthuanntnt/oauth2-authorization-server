# oauth2-authorization-server

OAuth2 Authorization Server Skeleton

## 1. Flow Authorization Request

```
Send request to 
http://127.0.0.1:8080/oauth2/authorize?response_type=code
&client_id=ntnt-oidc-client
&redirect_url=https://oauth.pstmn.io/v1/callback
&state=kjh812kiugh123iblj
```

```mermaid 
---
title: Flow Authorization Request
---
classDiagram
    note for OAuth2AuthorizationEndpointFilter "Convert Request Param to Authentication
                                                Then use AuthenticationManager to authenticate that Authentication"


    OAuth2AuthorizationEndpointFilter --> DelegatingAuthenticationConverter
    OAuth2AuthorizationEndpointFilter --> ProviderManager

    DelegatingAuthenticationConverter --|> AuthenticationConverter
    OAuth2AuthorizationCodeRequestAuthenticationConverter --|> AuthenticationConverter
    OAuth2AuthorizationConsentAuthenticationConverter --|> AuthenticationConverter
    DelegatingAuthenticationConverter --> OAuth2AuthorizationCodeRequestAuthenticationConverter
    DelegatingAuthenticationConverter --> OAuth2AuthorizationConsentAuthenticationConverter

    ProviderManager --|> AuthenticationManager
    ProviderManager --> OAuth2AuthorizationCodeRequestAuthenticationProvider
    note for ProviderManager "Contains up to 18 AuthenticationProviders 
                              but only OAuth2AuthorizationCodeRequestAuthenticationProvider that support "

    OAuth2AuthorizationCodeRequestAuthenticationProvider --|> AuthenticationProvider

    class OAuth2AuthorizationEndpointFilter {
        -AuthenticationConverter authenticationConverter
        -AuthenticationManager authenticationManager
        -AuthenticationSuccessHandler authenticationSuccessHandler
        -AuthenticationFailureHandler authenticationFailureHandler
    }
    class AuthenticationConverter {
        <<interface>>
        +convert(HttpServletRequest request)
    }
    class AuthenticationManager {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
    }
    class AuthenticationProvider {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }

    class DelegatingAuthenticationConverter {
        -List~AuthenticationConverter~ converters

        +convert(HttpServletRequest request)
    }
    class OAuth2AuthorizationCodeRequestAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class OAuth2AuthorizationConsentAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class ProviderManager {
        -List~AuthenticationProvider~ providers

        +Authentication authenticate(Authentication authentication)
    }
    class OAuth2AuthorizationCodeRequestAuthenticationProvider {
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
```

## 2. Flow login
```mermaid 
---
title: Flow Login
---
classDiagram
    AbstractAuthenticationProcessingFilter <|-- UsernamePasswordAuthenticationFilter
    AbstractAuthenticationProcessingFilter --> ProviderManager0

    ProviderManager0 --|> AuthenticationManager
    ProviderManager0 --> AnonymousAuthenticationProvider: providers
    ProviderManager0 --> ProviderManager1: parents

    ProviderManager1 --|> AuthenticationManager
    ProviderManager1 --> DaoAuthenticationProvider : providers

    DaoAuthenticationProvider --|> AbstractUserDetailsAuthenticationProvider
    AbstractUserDetailsAuthenticationProvider --|> AuthenticationProvider
    AnonymousAuthenticationProvider --|> AuthenticationProvider

    class AbstractAuthenticationProcessingFilter {
        <<abstract>>
        -AuthenticationManager authenticationManager
        void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    }
    class AuthenticationManager {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
    }
    class AuthenticationProvider {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }

    class UsernamePasswordAuthenticationFilter {
        +attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
    }
    class ProviderManager0 {
        -List~AuthenticationProvider~ providers
        -AuthenticationManager parent

        +Authentication authenticate(Authentication authentication)
    }
    class AnonymousAuthenticationProvider {
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
    class ProviderManager1 {
        -List~AuthenticationProvider~ providers
        -AuthenticationManager parent

        +Authentication authenticate(Authentication authentication)
    }
    class AbstractUserDetailsAuthenticationProvider{
        +Authentication authenticate(Authentication authentication)
    }
    class DaoAuthenticationProvider{
        -PasswordEncoder passwordEncoder
        -UserDetailsService userDetailsService
        -UserDetailsPasswordService userDetailsPasswordService
        
        +UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
    }
```
After Login Authentication (UsernamePasswordAuthenticationToken) is stored into Session (Using sessionId to retrieve it)

## 4. Flow Authorization Request After request
Same flow as **1. Flow Authorization Request**, but now we have Authentication (UsernamePasswordAuthenticationToken) 
in Session
Then after authenticate it will redirect consent screen **5. Flow Authorization Consent**

## 5. Flow Authorization Consent
```mermaid 
---
title: Flow Authorization Consent
---
classDiagram
    note for OAuth2AuthorizationEndpointFilter "Convert Request Param to Authentication
                                                Then use AuthenticationManager to authenticate that Authentication"

    OAuth2AuthorizationEndpointFilter --> DelegatingAuthenticationConverter
    OAuth2AuthorizationEndpointFilter --> ProviderManager

    DelegatingAuthenticationConverter --|> AuthenticationConverter
    OAuth2AuthorizationCodeRequestAuthenticationConverter --|> AuthenticationConverter
    OAuth2AuthorizationConsentAuthenticationConverter --|> AuthenticationConverter
    DelegatingAuthenticationConverter --> OAuth2AuthorizationCodeRequestAuthenticationConverter
    DelegatingAuthenticationConverter --> OAuth2AuthorizationConsentAuthenticationConverter

    ProviderManager --|> AuthenticationManager
    ProviderManager --> OAuth2AuthorizationConsentAuthenticationProvider
    note for ProviderManager "Contains up to 18 AuthenticationProviders 
                              but only OAuth2AuthorizationConsentAuthenticationProvider are supported"

    OAuth2AuthorizationConsentAuthenticationProvider --|> AuthenticationProvider
    OAuth2AuthorizationConsentAuthenticationProvider -- InMemoryOAuth2AuthorizationService
    InMemoryOAuth2AuthorizationService --|> OAuth2AuthorizationService
    note for InMemoryOAuth2AuthorizationService "This service is used to save every authorized client information 
    such as client_id, user_id, scope, authorization_code, and other attributes" 

    class OAuth2AuthorizationEndpointFilter {
        -AuthenticationConverter authenticationConverter
        -AuthenticationManager authenticationManager
        -AuthenticationSuccessHandler authenticationSuccessHandler
        -AuthenticationFailureHandler authenticationFailureHandler
    }
    class AuthenticationConverter {
        <<interface>>
        +convert(HttpServletRequest request)
    }
    class AuthenticationManager {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
    }
    class AuthenticationProvider {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
    class OAuth2AuthorizationService {
        <<interface>>
        +save(OAuth2Authorization authorization)
        +findById(String id)
    }

    class DelegatingAuthenticationConverter {
        -List~AuthenticationConverter~ converters

        +convert(HttpServletRequest request)
    }
    class OAuth2AuthorizationCodeRequestAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class OAuth2AuthorizationConsentAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class ProviderManager {
        -List~AuthenticationProvider~ providers

        +Authentication authenticate(Authentication authentication)
    }
    class OAuth2AuthorizationConsentAuthenticationProvider {
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
    class InMemoryOAuth2AuthorizationService {
        +save(OAuth2Authorization authorization)
        +findById(String id)
    }
```
After finishing authorize consent, it will redirect to **6. Flow Client Authentication**

## 6. Flow Client Authentication & Token Response
### 6.1 Flow Client Authentication
```mermaid
---
title: Flow Client Authentication
---
classDiagram
    OAuth2ClientAuthenticationFilter --> DelegatingAuthenticationConverter
    OAuth2ClientAuthenticationFilter --> ProviderManager
    
    DelegatingAuthenticationConverter --|> AuthenticationConverter
    note for DelegatingAuthenticationConverter "Contains 4 AuthenticationConverter 
                                                which are JwtClientAssertionAuthenticationConverter, 
                                                ClientSecretBasicAuthenticationConverter, 
                                                ClientSecretPostAuthenticationConverter, 
                                                PublicClientSecretBasicAuthenticationConverter, 
                                                But in this flow only ClientSecretBasicAuthenticationConverter, 
                                                or ClientSecretPostAuthenticationConverter are supported"
    DelegatingAuthenticationConverter --> ClientSecretBasicAuthenticationConverter
    DelegatingAuthenticationConverter --> ClientSecretPostAuthenticationConverter

    ProviderManager --|> AuthenticationManager
    ProviderManager --> ClientSecretAuthenticationProvider
    note for ProviderManager "Contains up to 18 AuthenticationProviders 
                              but only ClientSecretAuthenticationProvider are supported "

    class OAuth2ClientAuthenticationFilter {
        -AuthenticationConverter authenticationConverter
        -AuthenticationManager authenticationManager
        -AuthenticationSuccessHandler authenticationSuccessHandler
        -AuthenticationFailureHandler authenticationFailureHandler
    }

    class AuthenticationConverter {
        <<interface>>
        +convert(HttpServletRequest request)
    }
    class AuthenticationManager {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
    }
    class AuthenticationProvider {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
    
    class DelegatingAuthenticationConverter {
        -List~AuthenticationConverter~ converters

        +convert(HttpServletRequest request)
    }
    class ClientSecretBasicAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class ClientSecretPostAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class ProviderManager {
        -List~AuthenticationProvider~ providers

        +Authentication authenticate(Authentication authentication)
    }
    class ClientSecretAuthenticationProvider {
        +Authentication authenticate(Authentication authentication)
        
        +boolean supports(Class~?~ authentication)
    }
```
After finishing this flow it will trigger **6.2 Flow Token Response** 

### 6.2 Flow Token Response
```mermaid
---
title: Token Response
---
classDiagram

    OAuth2TokenEndpointFilter --> DelegatingAuthenticationConverter
    OAuth2TokenEndpointFilter --> ProviderManager

    DelegatingAuthenticationConverter --|> AuthenticationConverter
    note for DelegatingAuthenticationConverter "Contains 4 AuthenticationConverter which are
                                                OAuth2AuthorizationCodeAuthenticationConverter,
                                                OAuth2RefreshTokenAuthenticationConverter,
                                                OAuth2ClientCredentialsAuthenticationConverter,
                                                OAuth2DeviceCodeAuthenticationConverter but in this flow only 
                                                OAuth2AuthorizationCodeAuthenticationConverter are supported"
    DelegatingAuthenticationConverter --> OAuth2AuthorizationCodeAuthenticationConverter
    
    ProviderManager --|> AuthenticationManager
    ProviderManager --> OAuth2AuthorizationCodeAuthenticationProvider
    note for ProviderManager "Contains up to 18 AuthenticationProviders 
                              but only OAuth2AuthorizationCodeAuthenticationProvider are supported "

    class OAuth2TokenEndpointFilter {
        -AuthenticationConverter authenticationConverter
        -AuthenticationManager authenticationManager
        -AuthenticationSuccessHandler authenticationSuccessHandler
        -AuthenticationFailureHandler authenticationFailureHandler
    }

    class AuthenticationConverter {
        <<interface>>
        +convert(HttpServletRequest request)
    }
    class AuthenticationManager {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
    }
    class AuthenticationProvider {
        <<interface>>
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }

    class DelegatingAuthenticationConverter {
        -List~AuthenticationConverter~ converters

        +convert(HttpServletRequest request)
    }
    class OAuth2AuthorizationCodeAuthenticationConverter {
        +convert(HttpServletRequest request)
    }
    class ProviderManager {
        -List~AuthenticationProvider~ providers

        +Authentication authenticate(Authentication authentication)
    }
    class OAuth2AuthorizationCodeAuthenticationProvider {
        +Authentication authenticate(Authentication authentication)
        +boolean supports(Class~?~ authentication)
    }
```
After finishing this flow, This server will return the access token and refresh token to the OAuth2 Client to use it 
to access the resource server or access to the user profile endpoint.

