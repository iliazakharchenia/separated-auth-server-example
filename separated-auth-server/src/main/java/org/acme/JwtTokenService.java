package org.acme;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import io.quarkus.runtime.Startup;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.sql.Date;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Singleton
@Startup
public class JwtTokenService {
    private final String jwtSecret;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final String REFRESH_STRING = "\""+TokenType.REFRESH+"\"";
    private final String ACCESS_STRING = "\""+TokenType.ACCESS+"\"";

    public final String ROLES_DELIMITER;

    public JwtTokenService(@ConfigProperty(name = "jwt.access.secret") String jwtSecret,
                           @ConfigProperty(name = "security.roles-delimiter") String ROLES_DELIMITER) {
        this.jwtSecret = jwtSecret;
        this.ROLES_DELIMITER = ROLES_DELIMITER;
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
            var accessTokenObject = this.verifier.verify(access).getClaims();
            if (accessTokenObject.containsKey("type")) {
                var type = accessTokenObject.get("type").toString();
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

    public boolean validateAccessTokenAndCheckRoles(String access, Set<String> roles) {
        try {
            var accessTokenObject = this.verifier.verify(access).getClaims();
            if (accessTokenObject.containsKey("type")) {
                var type = accessTokenObject.get("type").toString();
                if (!Objects.equals(type, ACCESS_STRING))
                    throw new JWTVerificationException("Claim 'type' is not a '" + TokenType.ACCESS + "'!");

                var rolesString = accessTokenObject.get("roles").asString();
                var rolesSet = this.parseRoles(rolesString);
                boolean containsAllRoles = rolesSet.containsAll(roles);
                if (!containsAllRoles) throw new JWTVerificationException("No 'type' claim in the token!");

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

    public String buildRolesString(Set<String> roles) {
        if (roles.size() == 1) return roles.stream().findFirst().get();

        StringBuilder stringBuilder = new StringBuilder();
        roles.forEach(role -> {
            stringBuilder.append(role).append(this.ROLES_DELIMITER);
        });
        stringBuilder.deleteCharAt(stringBuilder.length()-1);

        return stringBuilder.toString();
    }

    public Set<String> parseRoles(String rolesString) {
        var roles = rolesString.split(this.ROLES_DELIMITER);
        return Set.of(roles);
    }
}
