package com.opp.todo.security;

import com.opp.todo.model.AppUser;
import lombok.Builder;

@Builder
public record LoginResponse(AppUser appUser,JwtResponse jwtResponse) {

}
