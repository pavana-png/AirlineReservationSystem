package com.flight.booking.controller;

import com.flight.booking.dto.AuthResponseDto;
import com.flight.booking.dto.LoginDto;
import com.flight.booking.dto.UserDto;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
    @Autowired
    private AuthController authController;
    private HttpServletResponse response;

    @GetMapping("/")
    public String greeting() {
        return "redirect:/register";
    }

    @GetMapping({"/register", "/register.html"})
    public String register(@RequestParam(name = "success", required = false) String success) {
        if (success != null && success.equals("true")) {
            return "redirect:/login";
        }
        return "register";
    }

    @PostMapping("/register")
    public String registerUserAccount(@ModelAttribute("user") UserDto userDto) {
        authController.register(userDto);
        return "redirect:/register?success=true";
    }

    @GetMapping({"/login", "/login.html"})
    public String login(@RequestParam(name = "success", required = false) String success) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/flights";
        } else if (success != null && success.equals("true")) {
            return "redirect:/login?success=true";
        } else {
            return "login";
        }
    }


    @PostMapping("/login")
    public String loginUserAccount(@ModelAttribute("user") LoginDto loginDto) {
        authController.login(loginDto, response);
        return "redirect:/flights";
    }

    @GetMapping({"/admin/login", "/adminLogin.html"})
    public String admin() {
        return "adminLogin";
    }

    @PostMapping("/admin/login")
    public String loginAdminUserAccount(@ModelAttribute("user") LoginDto loginDto) {
        ResponseEntity<AuthResponseDto> response = authController.adminLogin(loginDto);
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            return "redirect:/error";
        }
        return "redirect:/flights";
    }

}
