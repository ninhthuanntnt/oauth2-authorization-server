package com.ntnt.microservices.oauth2.authorization.server.config;

import com.ntnt.microservices.oauth2.authorization.server.helper.MfaHelper;
import com.ntnt.microservices.oauth2.authorization.server.repository.UserDomainRepository;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomDaoAuthenticationProvider;
import com.ntnt.microservices.oauth2.authorization.server.security.CustomSavedRequestAuthenticationSuccessHandler;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationFilter;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationProvider;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaAuthenticationToken;
import com.ntnt.microservices.oauth2.authorization.server.security.MfaTrustResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {
  public static final String MFA_URL = "/mfa";
  private final UserDomainRepository userDomainRepository;
  private final MfaHelper mfaHelper;
  private final DelegatingApplicationListener delegatingApplicationListener;

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .sessionManagement(sessionManagement -> sessionManagement.maximumSessions(2)
                                                                 .maxSessionsPreventsLogin(false))
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
        .securityContext(securityContext -> securityContext.securityContextRepository(securityContextRepository()))
        .authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests.requestMatchers("/assets/**",
                                                  "/static/**",
                                                  "/webjars/**",
                                                  "/login**",
                                                  "/error",
                                                  "/oauth2/token").permitAll()
                                 .requestMatchers(PathRequest.toH2Console()).permitAll()
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
        .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository())
                          .ignoringRequestMatchers(PathRequest.toH2Console()))
        .logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.GET.name())))
        .addFilterBefore(mfaAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    return httpSecurity.build();
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
  public SessionRegistry sessionRegistry() {
    SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
    delegatingApplicationListener.addListener(new GenericApplicationListenerAdapter(sessionRegistry));

    return sessionRegistry;
  }

  @Bean
  public CsrfTokenRepository csrfTokenRepository() {
    return new LazyCsrfTokenRepository(new HttpSessionCsrfTokenRepository());
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
    provider.setPasswordEncoder(passwordEncoder());
    provider.setUserDetailsService(userDetailsService);
    return provider;
  }

  @Bean
  public AuthenticationManager mfaAuthenticationManager() {
    return new ProviderManager(new MfaAuthenticationProvider(userDomainRepository, mfaHelper));
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
