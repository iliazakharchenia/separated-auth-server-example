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
import java.util.UUID;

@Singleton
public class JwtTokenService {
    private final String jwtSecret;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final String REFRESH_STRING = "\""+TokenType.REFRESH+"\"";
    private final String ACCESS_STRING = "\""+TokenType.ACCESS+"\"";

    public JwtTokenService(@ConfigProperty(name = "jwt.access.secret") String jwtSecret) {
        this.jwtSecret = jwtSecret;
        this.algorithm = Algorithm.HMAC256(this.jwtSecret);
        this.verifier = JWT.require(this.algorithm).build();
    }

    public boolean validateRefreshToken(String refresh) {
        try {
            var refreshTokenObject = this.verifier.verify(refresh).getClaims();
            if (refreshTokenObject.containsKey("type")) {
                var type = refreshTokenObject.get("type").toString();
                if (!Objects.equals(type.hashCode(), REFRESH_STRING.hashCode()))
                    throw new JWTVerificationException("Claim 'type' is not a '" + TokenType.REFRESH + "'!");

                return true;
            } else {
                throw new JWTVerificationException("No 'type' claim in the token!");
            }
        } catch (JWTVerificationException e) {
            System.out.println(e);
            return false;
        }
    }

    public String generateRefreshJwt() {
        var instantNow = Instant.now();
        var issuedAt = Date.from(instantNow);
        var expiresAt = Date.from(instantNow.plusSeconds(300));

        return JWT.create().withJWTId(UUID.randomUUID().toString())
                .withIssuer("jwt-auth-service")
                .withClaim("type", TokenType.REFRESH.toString())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(this.algorithm);
    }

    public String generateAccessJwt() {
        var instantNow = Instant.now();
        var issuedAt = Date.from(instantNow);
        var expiresAt = Date.from(instantNow.plusSeconds(60));

        return JWT.create().withJWTId(UUID.randomUUID().toString())
                .withIssuer("jwt-auth-service")
                .withClaim("type", TokenType.ACCESS.toString())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(this.algorithm);
    }
}
