package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/mypage")
    public String myPage() throws Exception {

        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createdUser(AccountDto accountDto) {
        userService.createUser(accountDto);
        return "redirect:/";
    }

}
