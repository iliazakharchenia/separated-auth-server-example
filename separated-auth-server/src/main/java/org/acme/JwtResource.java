package org.acme;

import io.smallrye.jwt.auth.principal.JWTParser;
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
        System.out.println("is valid " + isValid);

        return Uni.createFrom().item(Response.status(200).build());
        //return this.jwtTokenService.generateAccessToken().map(AccessJwt::from);
    }

    @GET
    @Path("/login")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> login(@RestHeader("username") String username,
                               @RestHeader("password") String password) {
        if (username == null || password == null)
            return Uni.createFrom().item(Response.status(400).build());

        return this.jwtTokenService.getTokenPair().map(tokenPair ->
                new TokenPair(tokenPair.access(), tokenPair.refresh()))
                    .map(tokenPair -> {
                        if (this.authorisationService.login(username, password))
                            return Response.ok(tokenPair).build();
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
