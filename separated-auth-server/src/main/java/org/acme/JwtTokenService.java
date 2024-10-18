package org.acme;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.sql.Date;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Singleton
public class JwtTokenService {
    private final String jwtSecret;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final String REFRESH_STRING = "\""+TokenType.REFRESH+"\"";
    private final String ACCESS_STRING = "\""+TokenType.ACCESS+"\"";

    public final String rolesDelimeter;

    public JwtTokenService(@ConfigProperty(name = "jwt.access.secret") String jwtSecret,
                           @ConfigProperty(name = "security.roles-delimeter") String rolesDelimeter) {
        this.jwtSecret = jwtSecret;
        this.rolesDelimeter = rolesDelimeter;
        this.algorithm = Algorithm.HMAC256(this.jwtSecret);
        this.verifier = JWT.require(this.algorithm).build();
    }

    public boolean validateRefreshToken(String refresh) {
        try {
            var refreshTokenObject = this.verifier.verify(refresh).getClaims();
            if (refreshTokenObject.containsKey("type")) {
                var type = refreshTokenObject.get("type").toString();
                if (!Objects.equals(type, REFRESH_STRING))
                    throw new JWTVerificationException("Claim 'type' is not a '" + TokenType.REFRESH + "'!");

                return true;
            } else {
                throw new JWTVerificationException("No 'type' claim in the token!");
            }
        } catch (JWTVerificationException e) {
            // log exception if needed
            return false;
        }
    }

    public boolean validateAccessToken(String access) {
        try {
            var refreshTokenObject = this.verifier.verify(access).getClaims();
            if (refreshTokenObject.containsKey("type")) {
                var type = refreshTokenObject.get("type").toString();
                if (!Objects.equals(type, ACCESS_STRING))
                    throw new JWTVerificationException("Claim 'type' is not a '" + TokenType.ACCESS + "'!");

                return true;
            } else {
                throw new JWTVerificationException("No 'type' claim in the token!");
            }
        } catch (JWTVerificationException e) {
            // log exception if needed
            return false;
        }
    }

    public String generateRefreshJwt(Set<String> roles) {
        var instantNow = Instant.now();
        var issuedAt = Date.from(instantNow);
        var expiresAt = Date.from(instantNow.plusSeconds(300));

        return JWT.create().withJWTId(UUID.randomUUID().toString())
                .withIssuer("jwt-auth-service")
                .withClaim("type", TokenType.REFRESH.toString())
                .withClaim("roles", buildRolesString(roles))
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(this.algorithm);
    }

    public String generateAccessJwt(Set<String> roles) {
        var instantNow = Instant.now();
        var issuedAt = Date.from(instantNow);
        var expiresAt = Date.from(instantNow.plusSeconds(60));

        return JWT.create().withJWTId(UUID.randomUUID().toString())
                .withIssuer("jwt-auth-service")
                .withClaim("type", TokenType.ACCESS.toString())
                .withClaim("roles", buildRolesString(roles))
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(this.algorithm);
    }

    public String generateAccessJwt(String refresh) {
        var instantNow = Instant.now();
        var issuedAt = Date.from(instantNow);
        var expiresAt = Date.from(instantNow.plusSeconds(60));
        var refreshTokenData = this.verifier.verify(refresh);
        var rolesString = refreshTokenData.getClaim("roles").asString();

        return JWT.create().withJWTId(UUID.randomUUID().toString())
                .withIssuer("jwt-auth-service")
                .withClaim("type", TokenType.ACCESS.toString())
                .withClaim("roles", rolesString)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(this.algorithm);
    }

    private String buildRolesString(Set<String> roles) {
        if (roles.size() == 1) return roles.stream().findFirst().get();

        StringBuilder stringBuilder = new StringBuilder();
        roles.forEach(role -> {
            stringBuilder.append(role).append(this.rolesDelimeter);
        });
        stringBuilder.deleteCharAt(stringBuilder.length()-1);

        return stringBuilder.toString();
    }
}
