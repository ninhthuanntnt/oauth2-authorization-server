package com.ntnt.microservices.oauth2.authorization.server.config;

import com.ntnt.microservices.oauth2.authorization.server.security.CustomDaoAuthenticationProvider;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomSavedRequestAuthenticationSuccessHandler;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationFilter;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationProvider;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationToken;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaTrustResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {
  public static final String MFA_URL = "/2fa";

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .securityContext(securityContext -> securityContext.securityContextRepository(securityContextRepository()))
        .authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests.requestMatchers("/assets/**",
                                                  "/static/**",
                                                  "/webjars/**",
                                                  "/login**",
                                                  "/error").permitAll()
                                 .requestMatchers(MFA_URL)
                                 .access((authentication, context) -> new AuthorizationDecision(authentication.get() instanceof MfaAuthenticationToken))
                                 .anyRequest().authenticated())
        .formLogin(formLogin -> formLogin.loginPage("/login")
                                         .successHandler(authenticationSuccessHandler()))
        .exceptionHandling(exceptionHandling ->
                               exceptionHandling.withObjectPostProcessor(new ObjectPostProcessor<ExceptionTranslationFilter>() {
                                 @Override
                                 public <O extends ExceptionTranslationFilter> O postProcess(O filter) {
                                   filter.setAuthenticationTrustResolver(new MfaTrustResolver());
                                   return filter;
                                 }
                               }))
        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository()))
        .addFilterBefore(mfaAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    return httpSecurity.build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails userDetails = User.builder()
                                  .username("user")
                                  .password("{noop}user")
                                  .roles("USER")
                                  .build();

    UserDetails userDetails2FA = User.builder()
                                     .username("user2fa")
                                     .password("{noop}user2fa")
                                     .roles("USER", "2FA")
                                     .build();

    return new InMemoryUserDetailsManager(userDetails, userDetails2FA);
  }

  @Bean
  public MfaAuthenticationFilter mfaAuthenticationFilter() {
    MfaAuthenticationFilter mfaAuthenticationFilter = new MfaAuthenticationFilter(new AntPathRequestMatcher(MFA_URL,
                                                                                                            "POST"),
                                                                                  mfaAuthenticationManager());
    mfaAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
    mfaAuthenticationFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
    mfaAuthenticationFilter.setSecurityContextRepository(securityContextRepository());
    mfaAuthenticationFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(MFA_URL + "?error"));
    return mfaAuthenticationFilter;
  }

  @Bean
  public AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new CustomSavedRequestAuthenticationSuccessHandler(MFA_URL);
  }


  @Bean
  public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new CompositeSessionAuthenticationStrategy(List.of(
        new ChangeSessionIdAuthenticationStrategy(),
        new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository()
        )));
  }

  @Bean
  public CsrfTokenRepository csrfTokenRepository() {
    return new HttpSessionCsrfTokenRepository();
  }

  @Bean
  public SecurityContextRepository securityContextRepository() {
    return new DelegatingSecurityContextRepository(
        new HttpSessionSecurityContextRepository(),
        new RequestAttributeSecurityContextRepository()
    );
  }

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService) {
    DaoAuthenticationProvider provider = new CustomDaoAuthenticationProvider();
    provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    provider.setUserDetailsService(userDetailsService);
    return provider;
  }

  @Bean
  public AuthenticationManager mfaAuthenticationManager() {
    return new ProviderManager(new MfaAuthenticationProvider());
  }
}
