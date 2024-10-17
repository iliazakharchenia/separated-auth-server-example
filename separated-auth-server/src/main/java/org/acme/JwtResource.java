package org.acme;

import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestHeader;

@Path("/jwt")
public class JwtResource {
    private final JwtTokenService jwtTokenService;
    private final AuthorisationService authorisationService;

    public JwtResource(JwtTokenService jwtTokenService, AuthorisationService authorisationService) {
        this.jwtTokenService = jwtTokenService;
        this.authorisationService = authorisationService;
    }

    @GET
    @Path("/access")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> getAccessToken(@RestHeader("refreshToken") String refresh) {
        if (refresh == null)
            return Uni.createFrom().item(Response.status(400).build());

        boolean isValid = this.jwtTokenService.validateRefreshToken(refresh);
        System.out.println("is valid: " + isValid);
        if (isValid) return Uni.createFrom().item(Response.ok(
                AccessJwt.from(this.jwtTokenService.generateAccessJwt())
        ).build());

        return Uni.createFrom().item(Response.status(401).build());
    }

    @GET
    @Path("/login")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> login(@RestHeader("username") String username,
                               @RestHeader("password") String password) {
        if (username == null || password == null)
            return Uni.createFrom().item(Response.status(400).build());

        return Uni.createFrom().item(this.authorisationService.login(username, password))
                    .map(loggedIn -> {
                        if (loggedIn)
                            return Response.ok(TokenPair.from(
                                    this.jwtTokenService.generateAccessJwt(),
                                    this.jwtTokenService.generateRefreshJwt())).build();

                        else return Response.status(401).build();
                    });
    }

    public record AccessJwt(String accessToken) {
        public static AccessJwt from(String accessTokenString) {
            return new AccessJwt(accessTokenString);
        }
    }

    public record TokenPair(String accessToken, String refreshToken) {
        public static TokenPair from(String accessTokenString, String refreshTokenString) {
            return new TokenPair(accessTokenString, refreshTokenString);
        }
    }
}
