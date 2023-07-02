package com.example.numblespringbatch.config;

import com.example.numblespringbatch.jwt.JwtAccessDeniedHandler;
import com.example.numblespringbatch.jwt.JwtAuthenticationEntryPoint;
import com.example.numblespringbatch.jwt.JwtSecurityConfig;
import com.example.numblespringbatch.jwt.TokenProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // h2-console 하위 모든 요청들, 파비콘 관련 요청은 Spring Security 로직을 수행하지 않는다
        return (web) -> web.ignoring().antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
        http
                .csrf().disable();

        http
                .authorizeRequests()
                .antMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll() // 해당 Request는 허용한다.
                .requestMatchers(PathRequest.toH2Console()).permitAll()
                .anyRequest().authenticated();

        // exception handling for jwt
        http
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler);

        // 세션을 사용하지 않기 때문에 STATELESS로 설정
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // enable h2-console
        http
                .headers().frameOptions().sameOrigin();

        // Apply JWT
        http
                .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }
}
