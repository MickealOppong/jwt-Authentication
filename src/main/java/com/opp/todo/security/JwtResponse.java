package com.opp.todo.security;

import lombok.Builder;

@Builder
public record JwtResponse(String accessToken,String token) {
}
