package com.example.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //subject has to be the username or email of the client
    }

    //method to extract single claim that we pass
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    //generate tokens
    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); //this will generate and return the token
    }

    public boolean isTokenValid(String token , UserDetails userDetails){
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && isTokenExpire(token);
    }

    private boolean isTokenExpire(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails); //this method is to generate a token without extra claims
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBite = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBite); //hamc is one of the algorithm
    }
}

//signInKey is a secret that is used to digitally sign in the JWT and this also helps to create the signature part of
// JWT which we use to verify that if a sender is who they claim to be and the message is not changed through the way
//signing key is used in conjunction with the sign in algorithm specified in JWT
//signing key and the algorithm depends on the security requirement of the application and the level of trust you have
//on the signed in party.

//minimum requirement for the size of the JWT token is 256 bit