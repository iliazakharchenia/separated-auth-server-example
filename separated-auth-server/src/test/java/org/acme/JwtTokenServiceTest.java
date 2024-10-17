package org.acme;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.*;

@QuarkusTest
class JwtTokenServiceTest {
    @Inject
    JwtTokenService jwtTokenService;

    @Test
    void validRefreshTokenRefreshTokenValidationShouldAnswerWithTheOkStatus() {
        String refresh = jwtTokenService.generateRefreshJwt();

        given()
                .header("refreshToken", refresh)
                .when().get("/jwt/access")
                .then()
                .statusCode(200);
    }

    @Test
    void validRefreshTokenRefreshTokenValidationShouldAnswerWithTheValidAccessTokenInTheBody() {
        String refresh = jwtTokenService.generateRefreshJwt();

        var accessTokenResponse = given()
                .header("refreshToken", refresh)
                .when().get("/jwt/access");

        var accessTokenOptions = accessTokenResponse.then().extract().body();
        var accessToken = accessTokenOptions.as(JwtResource.AccessJwt.class).accessToken();

        assert jwtTokenService.validateAccessToken(accessToken);
        given()
                .header("accessToken", accessToken)
                .when().get("/jwt/access-validate")
                .then()
                .statusCode(200);
    }
}
