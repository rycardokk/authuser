package com.ead.authuser.configs.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

@Log4j2
@Component
public class JwtProvider {

    @Value("${ead.auth.jwtKey}")
    private String jwtKey;
    @Value("${ead.auth.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwt(Authentication auth){
        UserDetailsImpl userPrincipal = (UserDetailsImpl) auth.getPrincipal();
        final String roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect((Collectors.joining(",")));
        SecretKey key = Keys.hmacShaKeyFor(jwtKey.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .subject(userPrincipal.getUserId().toString())
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    public String getSubjectJwt(String token) {
        return Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(jwtKey.getBytes(StandardCharsets.UTF_8))).build()
                        .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwt(String authToken) {
        try {
            Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtKey.getBytes(StandardCharsets.UTF_8))).build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (SecurityException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e){
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e){
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }


}
