package org.acme;

import io.quarkus.runtime.Startup;
import io.smallrye.mutiny.Uni;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestHeader;
import org.jboss.resteasy.reactive.RestQuery;

@Path("/jwt")
@Startup
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
    public Uni<Response> getAccessToken(@NotNull @RestHeader("refreshToken") String refresh) {
        return Uni.createFrom().item(refresh)
                .map(token -> {
                    if (this.jwtTokenService.validateRefreshToken(token)) return Response.ok(
                            AccessJwt.from(this.jwtTokenService.generateAccessJwt(refresh))
                    ).build();
                    else return Response.status(401).build();
                });
    }

    @GET
    @Path("/access-validate")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> validateAccessToken(@NotNull @RestHeader("accessToken") String access) {
        return Uni.createFrom().item(access)
                .map(token -> {
                    if (this.jwtTokenService.validateAccessToken(token)) return Response.ok().build();
                    else return Response.status(401).build();
                });
    }

    @GET
    @Path("/access-validate-roles")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> validateAccessTokenWithRoles(@NotNull @RestHeader("accessToken") String access,
                                                      @NotNull @RestHeader("rolesToCheck") String rolesString) {
        return Uni.createFrom().item(access)
                .map(token -> {
                    if (this.jwtTokenService.validateAccessTokenAndCheckRoles(token,
                            this.jwtTokenService.parseRoles(rolesString))) return Response.ok().build();
                    else return Response.status(401).build();
                });
    }

    @GET
    @Path("/login")
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> login(@NotNull @NotBlank @RestHeader("username") String username,
                               @NotNull @NotBlank @RestHeader("password") String password) {
        return Uni.createFrom().item(this.authorisationService.login(username, password))
                .map(userData -> Response.ok(TokenPair.from(
                            this.jwtTokenService.generateAccessJwt(userData.roles()),
                            this.jwtTokenService.generateRefreshJwt(userData.roles()))
                ).build())
                .replaceIfNullWith(() -> Response.status(401).build());
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
