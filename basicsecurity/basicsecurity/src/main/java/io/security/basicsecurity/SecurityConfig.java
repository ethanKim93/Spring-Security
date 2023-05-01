//package io.security.basicsecurity;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.access.AccessDeniedException;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.context.SecurityContext;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.provisioning.UserDetailsManager;
//import org.springframework.security.web.AuthenticationEntryPoint;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.access.AccessDeniedHandler;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.authentication.logout.LogoutHandler;
//import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
//import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import javax.servlet.http.HttpSession;
//import java.io.IOException;
//
//// 강의 내용
//@Configuration
//@EnableWebSecurity // 여러 Class를 가지고 있음 ,웹보안이 활성화 됨
//public class SecurityConfig {
////    @Autowired
////    UserDetailsService userDetailService;
//
//    //임시 유저 만들기기
//   @Bean
//    public UserDetailsManager users() {
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password("{noop}1111") //{noop} password를 암호화 할때 어떤 유형인지 기재
//                .roles("USER")
//                .build();
//
//        UserDetails sys = User.builder()
//                .username("sys")
//                .password("{noop}1111")
//                .roles("SYS")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password("{noop}1111")
//                .roles("ADMIN", "SYS", "USER") // 권한을 여러개 할당
//                .build();
//
//        return new InMemoryUserDetailsManager( user, sys, admin );
//    }
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/login").permitAll() // 로그인 페이지는 모든 권한 접근을 허용해줘야함
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")// 좁은 범위의 경로가 더 위로 외야함.
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // 넓은 범위의 경로가 더 아래로 외야함.
//                .anyRequest().permitAll(); // 이외의 요청도 인증을 받은 사용자만
//
//        http.formLogin()
//                .loginPage("/loginPage") // 인증을 받지 않아도 누구나 접근 가능해야함
//                .defaultSuccessUrl("/").usernameParameter("userId").passwordParameter("passwd").loginProcessingUrl("/login_proc").successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                }).failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                }).successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache(); // 사용자의 요청정보를 이 클래스를 사용하여 저장 // 인증이 실패 했을때 사용자 정보를 cache에 보관
//                        SavedRequest savedRequest = requestCache.getRequest(request,response); // savedRequest 세션에서 꺼내서 원래 요청을 꺼냄
//                        String redirectUrl = savedRequest.getRedirectUrl(); // 원래 사용자가 요청한 url 정보를 찾을 수 있음
//                        response.sendRedirect(redirectUrl); // 세션에 있던 정보로 보냄
//                    }
//                })
//                .permitAll();// 누구나 허용
//        http.logout().logoutUrl("/logout").logoutSuccessUrl("/login").addLogoutHandler(new LogoutHandler() {
//            @Override
//            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                HttpSession session = request.getSession();
//                session.invalidate(); // 세션 만료
//
//            }
//        }).logoutSuccessHandler(new LogoutSuccessHandler() { // logoutSuccessUrl과 유사하지만 logoutSuccessUrl은 경로만 설정가능하고 핸들러는 더 많은 기능을 설정 할 수 있음
//            @Override
//            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                response.sendRedirect("/login");
//            }
//        }).deleteCookies("remember-me") // 쿠키 삭제
//        ;
//
//        http
//                .rememberMe()
//                .rememberMeParameter("remember").
//                tokenValiditySeconds(3600)
//                .alwaysRemember(true);
////                .userDetailsService(userDetailService); //읽는 놈이 조회시
//
//         http
//                 .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint(){ // 인증 에러 발생
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedPage("/denied")
//                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 예외
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        response.sendRedirect("/denied");
//                    }
//                });
//
//         //SecurityContextHolder 모드 변경
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
//        return http.build();
//    }
//
//}