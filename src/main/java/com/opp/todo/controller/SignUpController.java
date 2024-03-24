package com.opp.todo.controller;

import com.opp.todo.exceptions.UsernameAlreadyExistException;
import com.opp.todo.model.AppUser;
import com.opp.todo.security.SignUpRequest;
import com.opp.todo.service.AppUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sign-up")
public class SignUpController {


    private AppUserService userService;
    private PasswordEncoder passwordEncoder;

    public SignUpController(AppUserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/user")
    private ResponseEntity<String> addUser(@RequestBody SignUpRequest signUpRequest){
        try{
            AppUser newUser = new AppUser(signUpRequest.username(),signUpRequest.name(), passwordEncoder.encode(signUpRequest.password()));
            AppUser user= userService.addUser(newUser);
                return ResponseEntity.ok().body("user created");
        }catch(UsernameAlreadyExistException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
