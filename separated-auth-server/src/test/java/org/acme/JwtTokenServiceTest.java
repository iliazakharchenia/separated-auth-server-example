package org.acme;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static io.restassured.RestAssured.*;

@QuarkusTest
class JwtTokenServiceTest {
    @Inject
    JwtTokenService jwtTokenService;

    @Test
    void validRefreshTokenRefreshTokenValidationShouldAnswerWithTheOkStatus() {
        String refresh = jwtTokenService.generateRefreshJwt(Set.of("USER", "READ"));

        given()
                .header("refreshToken", refresh)
                .when().get("/jwt/access")
                .then()
                .statusCode(200);
    }

    @Test
    void validRefreshTokenCanBeUsedForGeneratingTheValidAccessTokenInTheBodyAfterRequestAccessToken() {
        String refresh = jwtTokenService.generateRefreshJwt(Set.of("USER"));

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

    @Test
    void accessTokenWithRolesSetShouldBeCheckedCorrectly() {
        String firstAccessToken = jwtTokenService.generateAccessJwt(Set.of("USER"));
        String secondAccessToken = jwtTokenService.generateAccessJwt(Set.of("USER", "MANAGER"));

        // first token asserts
        assert jwtTokenService.validateAccessTokenAndCheckRoles(firstAccessToken, Set.of("USER"));
        assert !jwtTokenService.validateAccessTokenAndCheckRoles(firstAccessToken, Set.of("MANAGER"));
        assert !jwtTokenService.validateAccessTokenAndCheckRoles(firstAccessToken, Set.of("USER", "MANAGER"));

        // second token asserts
        assert !jwtTokenService.validateAccessTokenAndCheckRoles(secondAccessToken, Set.of("INTRUDER"));
        assert jwtTokenService.validateAccessTokenAndCheckRoles(secondAccessToken, Set.of("USER"));
        assert jwtTokenService.validateAccessTokenAndCheckRoles(secondAccessToken, Set.of("USER", "MANAGER"));
        assert jwtTokenService.validateAccessTokenAndCheckRoles(secondAccessToken, Set.of("MANAGER"));
    }
}
