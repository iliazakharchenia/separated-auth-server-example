package org.acme;

import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Objects;
import java.util.Set;

@Singleton
public class JwtTokenService {
    @ConfigProperty(name = "jwt.access.secret")
    private String jwtSecret;
    private final JWTParser jwtParser;

    public JwtTokenService(JWTParser jwtParser) {
        this.jwtParser = jwtParser;
    }

    public Uni<TokenPair> getTokenPair() {
        return Uni.createFrom().item(() ->
                new TokenPair(generateAccessJwt(), generateRefreshJwt()));
    }

    public Uni<String> generateAccessToken() {
        return Uni.createFrom().item(this::generateAccessJwt);
    }

    public boolean validateRefreshToken(String refresh) {
        try {
            var refreshTokenObject = this.jwtParser.decrypt(refresh, this.jwtSecret);
            if (refreshTokenObject.containsClaim("type")) {
                var type = refreshTokenObject.getClaim("type").toString();
                if (!Objects.equals(type, TokenType.REFRESH.toString()))
                    throw new ParseException("Claim 'type' is not a '" + TokenType.REFRESH + "'!");
            } else {
                throw new ParseException("No 'type' claim in the token!");
            }
        } catch (ParseException e) {
            System.out.println(e.getMessage());
        }

        return false;
    }

    private String generateRefreshJwt() {
        return Jwt.issuer("jwt-auth-service")
                .claim("type", TokenType.REFRESH.toString())
                .expiresAt(System.currentTimeMillis() + 300)
                .signWithSecret(jwtSecret);
    }

    private String generateAccessJwt() {
        return Jwt.issuer("jwt-auth-service")
                .claim("type", TokenType.ACCESS.toString())
                .groups(Set.of("user", "reader"))
                .expiresAt(System.currentTimeMillis() + 120)
                .signWithSecret(jwtSecret);
    }

    record TokenPair(String access, String refresh) {}
}
