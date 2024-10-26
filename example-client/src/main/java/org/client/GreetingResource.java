package org.client;

import io.quarkus.runtime.Startup;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.authclient.core.AuthenticationClient;
import org.jboss.resteasy.reactive.RestHeader;

@Path("/hello")
@Singleton
@Startup
public class GreetingResource {
    private final AuthenticationClient authenticationClient;

    public GreetingResource(AuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    @GET
    @Path("/public")
    @Produces(MediaType.TEXT_PLAIN)
    public Uni<Response> publicHello() {
        return Uni.createFrom()
                .item(Response.ok("Hello from public endpoint!").build());
    }

    @GET
    @Path("/authenticated")
    @Produces(MediaType.TEXT_PLAIN)
    public Uni<Response> authenticatedHello(@RestHeader("accessToken") String accessToken) {
        return authenticationClient.fromAccessToken(
                accessToken,
                Uni.createFrom().item(Response.ok("Hello from authenticated endpoint!").build()),
                Uni.createFrom().item(Response.status(401).build())
        );
    }
}
