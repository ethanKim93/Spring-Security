package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.URI;
import java.security.Security;
import java.util.*;

@RestController
public class SecurityController {

    private final SessionRegistry sessionRegistry ;
    private LogoutHandler handlers = new CompositeLogoutHandler(new LogoutHandler[]{new SecurityContextLogoutHandler()});
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    @Autowired
    public SecurityController(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }


    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }


    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/csrf")
    public ResponseEntity<String> getOrCreateCsrfToken(HttpServletRequest request) {
        HttpSession session = request.getSession();
        DefaultCsrfToken csrfToken = (DefaultCsrfToken) session.getAttribute("CSRF_TOKEN");

        return ResponseEntity.ok()
                .header(csrfToken.getHeaderName(), csrfToken.getToken()).body("Check your response header!");
    }

    //securityContext 확인
    @GetMapping("/securityContext")
    public String getSecurityContext(HttpSession session) {
        //방법 1
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //방법2
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication(); // authentication1 authentication1은 동일한 객체

        return  "securityContext";
    }

    @GetMapping("/thread")
    public void thread() {
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                    }
                }
        );
    }


    //기존 사용자를 만료시키고 login으로 redirect 하는 api

    /*
    기존 사용자를 만료시키고 로그인하는 로직

    sessionRegistry.getAllSessions에서 session을 찾을때 user 객체가 필요하다 .
    user 객체는 equals에서 username만 비교 하기 때문에  request에서 받은 id만 넣어줘도 되지만
    password나 grantedAuthority이 null일 경우 nullpoint exception 에러가 발생해서 임의의 값만들어 User 생성자에 입력하였다.

    (현재의 경우 ID만 일치하면 세션을 만료시키기 때문에 PW까지 확인하여 유요한 요청인지 확인하는 추가 로직이 필요하다.)

    request.setAttribute와 ModelAndView를 통해서 login으로 보낸다
    들어온 요청이 post 방식이였기때문에 그대로 setAttribute 하면 POST 로 요청이 보내진다.

    실제로직은 service에 구현한다.
    */
    @PostMapping("/expire")
    public ModelAndView expire(HttpServletRequest request, HttpServletResponse response, RedirectAttributes redirect) {
        String id = request.getParameter("id");
        String password = request.getParameter("password");
        List<GrantedAuthority >grantedAuthoritys = new ArrayList<>();

        GrantedAuthority grantedAuthority = new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return "none";
            }
        };

        grantedAuthoritys.add(grantedAuthority);
        User user = new User(id,password,grantedAuthoritys);
        SessionRegistry d = sessionRegistry;
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(user, false);
//        List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(id, false);

//        sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
//        int maximumSessionsExceededBy = sessions.size();
//        List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
//        Iterator var6 = sessionsToBeExpired.iterator();

        Iterator var6 = sessions.iterator();
        while(var6.hasNext()) {
            SessionInformation session = (SessionInformation)var6.next();
            session.expireNow();
        }

        //redirect Code
//
//        Map<String, String> map = new HashMap<String, String>();
//        map.put("id", id);
//        map.put("password", password);
//        redirect.addFlashAttribute("map", map);

//        HttpHeaders headers = new HttpHeaders();
//        headers.setLocation(URI.create("/login"));
//        return new ResponseEntity<>(headers, HttpStatus.MOVED_PERMANENTLY);
        request.setAttribute(
                View.RESPONSE_STATUS_ATTRIBUTE, HttpStatus.TEMPORARY_REDIRECT);
        return new ModelAndView("redirect:/login");
//        return "redirect:/login";

    }
    private void doLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        this.handlers.logout(request, response, auth);
    }

//    @GetMapping("re")
//    public String re(HttpServletRequest request){
////        System.out.println(request.getSession());
//        HttpSession session = request.getSession();
//        String name = (String) session.getAttribute("user");
//
//        System.out.println(name);
//
//        return "HttpServletRequest";
//    }
    }
