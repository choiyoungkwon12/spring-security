package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping(value = "/login")
    public String login(@RequestParam(value = "error", required = false) String error,
        @RequestParam(value = "exception", required = false) String exception, Model model) {

        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "login";
    }

    @GetMapping("/denied")
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String accountName =  (String)authentication.getPrincipal();
        model.addAttribute("username", accountName);
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }

}
