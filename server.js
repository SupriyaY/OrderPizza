const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./auth_config.json");

app.use(morgan("dev"));
app.use(helmet());
// Serve static assets from the public folder
app.use(express.static(join(__dirname, "public")));

// This is the endpoint to serve the configuration files 
app.get("/auth_config.json", (req, res) => {
    res.sendFile(join(__dirname, "auth_config.json"));
});


// JWT validation middleware
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`
    }),

    audience: authConfig.audience,
    issuer: `https://${authConfig.domain}/`,
    algorithms: ["RS256"]
});

// Create an endpoint that uses the middleware to protect this route from unthorized requests
app.get("/api/external", checkJwt, (req, res) => {
    res.send({
        msg: "Your access token was successfully validated!"
    });
});


// Serve the index page for all other requests
app.get("/*", (_, res) => {
    res.sendFile(join(__dirname, "index.html"));
});


// Error handling
app.use(function(err, req, res, next) {
    if (err.name === "UnauthorizedError") {
        return res.status(401).send({ msg: "Invalid token" });
    }

    next(err, req, res);
});

process.on("SIGINT", function() {
    process.exit();
});

module.exports = app;