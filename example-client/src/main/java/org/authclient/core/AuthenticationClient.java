package org.authclient.core;

import io.quarkus.runtime.Startup;
import io.smallrye.common.constraint.NotNull;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Startup
@Singleton
public class AuthenticationClient {
    private final HttpClient httpClient;
    private final String host;
    private final String accessTokenValidationUrl;

    public final String accessTokenHeaderName;
    public final String refreshTokenHeaderName;

    public AuthenticationClient(@NotNull @ConfigProperty(name = "auth.client.host")
                                    String host,
                                @NotNull @ConfigProperty(name = "auth.client.accessTokenHeader")
                                    String accessTokenHeaderName,
                                @NotNull @ConfigProperty(name = "auth.client.accessTokenValidationUri")
                                    String accessTokenValidationUri,
                                @NotNull @ConfigProperty(name = "auth.client.accessTokenUpdateUri")
                                    String accessTokenUpdateUri,
                                @NotNull @ConfigProperty(name = "auth.client.loginUri")
                                    String loginUri,
                                @NotNull @ConfigProperty(name = "auth.client.refreshTokenHeader")
                                    String refreshTokenHeaderName) {
        this.httpClient = HttpClient.newHttpClient();
        this.accessTokenHeaderName = accessTokenHeaderName;
        this.refreshTokenHeaderName = refreshTokenHeaderName;
        this.host = host;
        this.accessTokenValidationUrl = host + accessTokenValidationUri;
    }

    public Uni<Response> fromAccessToken(String token, Uni<Response> onSuccess, Uni<Response> onFail) {
        if (token == null) return Uni.createFrom().item(Response.status(401).build());

        return Uni.createFrom().item(token)
                .map(accessToken -> {
                    var httpRequest = HttpRequest
                            .newBuilder(URI.create(this.accessTokenValidationUrl))
                            .header(this.accessTokenHeaderName, token)
                            .GET()
                            .build();

                    try {
                        int status = this.httpClient
                                        .send(httpRequest, HttpResponse.BodyHandlers.ofString())
                                        .statusCode();

                        if (status == 200 || status == 201) return Response.status(status).build();

                        throw new RuntimeException("Response status "+status+" is unacceptable!");
                    } catch (IOException | InterruptedException e) {
                        // log if needed
                        throw new RuntimeException(e);
                    }
                })
                .onItem().transformToUni(item -> onSuccess)
                .onFailure().recoverWithUni(onFail);
    }
}
