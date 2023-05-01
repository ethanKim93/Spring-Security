package io.security.basicsecurity;


import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.IOException;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;


//import com.tistory.handler.LoginSuccessHandler;


@Configuration
@EnableWebSecurity // 1-1. 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig_dev {

    private static SessionRegistry sessionRegistry = new SessionRegistryImpl();

    // 1-2. WebSecurityConfigurerAdapter를 상속해서 AuthenticationManager를 bean으로 등록했던걸 직접 등록.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsManager users() {

        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111") //{noop} password를 암호화 할때 어떤 유형인지 기재
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER") // 권한을 여러개 할당
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }


    // 1-3. 기존 SecurityConfig에서 configure 메소드 기능을 한다.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/login").permitAll() // 로그인 페이지는 모든 권한 접근을 허용해줘야함
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")// 좁은 범위의 경로가 더 위로 외야함.
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // 넓은 범위의 경로가 더 아래로 외야함.
                .anyRequest().permitAll(); // 이외의 요청도 인증을 받은 사용자만

        http.formLogin().usernameParameter("id").passwordParameter("password").defaultSuccessUrl("/")
//                .successHandler(new AuthenticationSuccessHandler() {
//            @Override
//            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                boolean isExpire = false;
//                Cookie[] cookies = request.getCookies();
//                for (Cookie cookie : cookies) {
//                    if (cookie.getName().equals("isExpire")) {
//                        isExpire = Boolean.parseBoolean(cookie.getValue());
//                    }
//                }
//                if (isExpire) {
//                    Object priciopal = authentication.getPrincipal();
//                    List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
//                    sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
//                    int maximumSessionsExceededBy = sessions.size() - 1;
//                    List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
//                    Iterator var6 = sessionsToBeExpired.iterator();
//
//                    while (var6.hasNext()) {
//                        SessionInformation session = (SessionInformation) var6.next();
//                        session.expireNow();
//                    }
//                    System.out.println("expire True");
//                    return;
//                }
//                System.out.println("expire False");
//                response.sendRedirect("/");
//
//            }
//        })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//
//                    }
//                })
        ;

        http.csrf()
//                .disable()
                .csrfTokenRepository(httpSessionCsrfTokenRepository())
//                .csrfTokenRepository(new CookieCsrfTokenRepository())
        ;
        http.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true).expiredUrl("/duplicated-login")
                .sessionRegistry(sessionRegistry());

        http.logout().logoutUrl("/logout").logoutSuccessUrl("/login").addLogoutHandler(new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response,
                               Authentication authentication) {
                HttpSession session = request.getSession();
                session.invalidate(); // 세션 만료
            }
        }).deleteCookies("remember-me") // 쿠키 삭제
        ;

        ;
        return http.build();

    }

//// 1-12. 정적 파일 인증 무시.(2.7.0이상 부터는 이런 방식으로 설정. -> 임시로 bean으로 등록은 안해놓음)
//   public WebSecurityCustomizer webSecurityCustomizer() {
//      WebSecurityCustomizer web = new WebSecurityCustomizer() {
//
//         @Override
//         public void customize(WebSecurity web) {
//            web.ignoring().antMatchers("/tistory/css/**", "/tistory/image/**", "/tistory/js/**");
//         }
//
//      };
//
//      return web;
//   }

    // 1-11. 비밀빈호 해시
//    @Bean
//    public BCryptPasswordEncoder encode() {
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public static SessionRegistry sessionRegistry() {
        return sessionRegistry;
//        return new SessionRegistryImpl();
    }

    @Bean
    public static ServletListenerRegistrationBean httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
    }

    @Bean
    public HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository() {
        HttpSessionCsrfTokenRepository csrfRepository = new HttpSessionCsrfTokenRepository();
        // 아래와 같이 설정하지 않으면
        // 기본값은 "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN" 입니다.
        csrfRepository.setSessionAttributeName("CSRF_TOKEN");
        return csrfRepository;
    }
}