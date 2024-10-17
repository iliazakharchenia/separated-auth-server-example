package org.acme;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

@QuarkusTest
class JwtTokenServiceTest {
    @Inject
    JwtTokenService jwtTokenService;

    @Test
    void validateRefreshToken() {
        String refresh = jwtTokenService.generateRefreshJwt();

        given()
                .header("refreshToken", refresh)
                .when().get("/jwt/access")
                .then()
                .statusCode(200);
    }
}
