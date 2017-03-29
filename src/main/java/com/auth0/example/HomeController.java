package com.auth0.example;

import com.auth0.SessionUtils;
import com.auth0.jwt.JWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@SuppressWarnings("unused")
@Controller
public class HomeController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(value = "/portal/home", method = RequestMethod.GET)
    protected String home(final Map<String, Object> model, final HttpServletRequest req) {
        logger.info("Home page");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!(principal instanceof Auth0User)) {
            return "redirect:/logout";
        }
        Auth0User user = ((Auth0User) principal);


        String accessToken = (String) SessionUtils.get(req, "accessToken");
        String idToken = (String) SessionUtils.get(req, "idToken");
        if (accessToken != null) {
            model.put("userId", JWT.decode(accessToken).getSubject());
        } else if (idToken != null) {
            model.put("userId", JWT.decode(idToken).getSubject());
        }
        return "home";
    }

}
