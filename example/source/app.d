import vibe.d;

import fastjwt.jwt;
import fastjwt.stringbuf;

string secret = "SuperStrongPassword";
JWTAlgorithm algo = JWTAlgorithm.HS512;

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8080;
	settings.bindAddresses = ["::1", "127.0.0.1"];
	auto router = new URLRouter();
	router.get("/login", &login);
	router.get("/secureapi", &validator!securedApi);

	listenHTTP(settings, router);
	logInfo("Please open http://127.0.0.1:8080/ in your browser.");
}

void login(HTTPServerRequest req, HTTPServerResponse res) {
	StringBuffer buf;
	encodeJWTToken(buf, algo, secret, "sub", 1337);
	res.writeBody(buf.getData());
}

void validator(alias fun)(HTTPServerRequest req,
		HTTPServerResponse res)
{
	import std.algorithm.searching : startsWith;

	auto authStr = "Authorization";
	auto bearer = "Bearer ";

	if(authStr !in req.headers || !req.headers[authStr].startsWith(bearer)) {
		res.writeBody("Get out, you're not welcome");
		return;
	}

	StringBuffer header;
	StringBuffer payload;
	const rslt = decodeJWTToken(req.headers[authStr][bearer.length .. $],
			secret, algo, header, payload);

	if(rslt > 0) {
		res.writeBody("Your token was not OK");
		return;
	}

	fun(req, res);
}

void securedApi(HTTPServerRequest req, HTTPServerResponse res) {
	res.writeBody("Here is your secure api!");
}
