const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const { join } = require("path");
const jwtAuthz = require('express-jwt-authz')
const authConfig = require("./auth_config.json");


const app = express();

if (!authConfig.domain || !authConfig.audience) {
    throw "Please make sure that auth_config.json is in place and populated";
}

app.use(morgan("dev"));
app.use(helmet());
app.use(express.static(join(__dirname, "public")));

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


// const checkScopes = jwtAuthz(['read:todos']);

app.get('/api/private', checkJwt, function(req, res) {
    res.json({ message: "Hello from a private endpoint! You need to be authenticated" });
});


const checkScopes = jwtAuthz(['read:messages']);

app.get('/api/private', checkJwt, checkScopes, function(req, res) {
    res.json({
        message: 'Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.'
    });
});


app.get("/auth_config.json", (req, res) => {
    res.sendFile(join(__dirname, "auth_config.json"));
});

app.get("/*", (req, res) => {
    res.sendFile(join(__dirname, "index.html"));
});


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