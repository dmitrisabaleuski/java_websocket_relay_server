package org.example;

import static spark.Spark.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.json.JSONObject;

import static org.example.ServerSecret.SECRET;

public class TokenHttpServer {

    public static void start(int port) {
        String portStr = System.getenv().getOrDefault("API_PORT", String.valueOf(port));
        port(Integer.parseInt(portStr));

        post("/api/token", (req, res) -> {
            JSONObject json = new JSONObject(req.body());
            String userId = json.optString("userId");

            if (isValidUser(userId)) {
                Algorithm algorithm = Algorithm.HMAC256(SECRET);
                String token = JWT.create()
                        .withSubject(userId)
                        .withIssuedAt(new java.util.Date())
                        .sign(algorithm);
                res.status(200);
                res.type("text/plain");
                return token;
            } else {
                res.status(401);
                return "Unauthorized";
            }
        });
    }

    private static boolean isValidUser(String userId) {
        return userId != null && !userId.isEmpty();
    }
}