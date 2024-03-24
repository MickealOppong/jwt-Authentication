package com.opp.todo.controller;

import com.opp.todo.model.AppUser;
import com.opp.todo.security.*;
import com.opp.todo.service.AppUserService;
import com.opp.todo.service.RefreshTokenService;
import com.opp.todo.service.UserTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthenticationManager authManager;
    private UserTokenService userTokenService;
    private RefreshTokenService refreshTokenService;
    private AppUserService appUserService;

    public AuthController(AuthenticationManager authManager, UserTokenService userTokenService,
                          RefreshTokenService refreshTokenService,AppUserService appUserService) {
        this.authManager = authManager;
        this.userTokenService = userTokenService;
        this.refreshTokenService = refreshTokenService;
        this.appUserService = appUserService;
    }


    @GetMapping
    public String home(){
        return "hello, this is authentication endpoint";
    }

    @PostMapping("/token")
    public String getToken(@RequestBody AuthRequest authRequest) {

       Authentication authentication = authManager
               .authenticate(new UsernamePasswordAuthenticationToken(authRequest.username(),authRequest
                       .password()));
    return userTokenService.token(authentication);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> createToken(@RequestBody AuthRequest authRequest){
       Optional<RefreshToken> userToken= refreshTokenService.getById(authRequest.username());
        if (userToken.isPresent()){
            JwtResponse jwtResponse = JwtResponse.builder()
                    .accessToken(userTokenService.token(authRequest.username()))
                    .token(userToken.get().getToken())
                    .build();
            AppUser appUser = appUserService.getUser(authRequest.username());
            LoginResponse loginResponse = LoginResponse.builder()
                    .appUser(appUser)
                    .jwtResponse(jwtResponse)
                    .build();
            return ResponseEntity.ok().body(loginResponse);

        }
        try {
                Authentication authentication = authManager
                        .authenticate(new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest
                                .password()));
                if (authentication.isAuthenticated()) {
                    RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequest.username());
                    // jwt token and refresh token generated
                    JwtResponse jwtResponse = JwtResponse.builder()
                            .accessToken(userTokenService.token(authentication))
                            .token(refreshToken.getToken()).build();
                    AppUser appUser = appUserService.getUser(authRequest.username());
                    // user queried from database
                    LoginResponse loginResponse = LoginResponse.builder()
                            .appUser(appUser)
                            .jwtResponse(jwtResponse)
                            .build();
                    //returning user data and jwt
                    return ResponseEntity.ok().body(loginResponse);
                }else{
                    throw new AuthenticationServiceException("Could not authenticate user");
                }

        } catch (Exception e) {
                throw new AuthenticationServiceException("Could not authenticate user");
        }

    }

    @PostMapping("/refreshToken")
    public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
        return refreshTokenService.findToken(refreshTokenRequest.token())
                .map(refreshTokenService::verifyExpirationTime)
                .map(RefreshToken::getUser)
                .map(todoUser -> {
                    String accessToken = userTokenService.token(todoUser.getUsername());
                    return JwtResponse.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequest.token())
                            .build();
                }).get();
    }



    @DeleteMapping("/logout")
    public ResponseEntity<String> removeToken(@RequestParam String token){
       RefreshToken refreshToken = refreshTokenService.removeToken(token);
        if(token !=null){
            return ResponseEntity.ok().body("Token deleted");
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Was not able to delete token");
    }
}
