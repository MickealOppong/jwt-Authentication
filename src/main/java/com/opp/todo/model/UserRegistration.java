package com.opp.todo.model;

import org.springframework.security.crypto.password.PasswordEncoder;

public class UserRegistration {

    private AppUser appUser;

    public UserRegistration(AppUser appUser){
        this.appUser = appUser;
    }

    public AppUser toUser(PasswordEncoder passwordEncoder){
        return new AppUser(appUser.getUsername(), appUser.getName(),passwordEncoder.encode(appUser.getPassword()));
    }
}
