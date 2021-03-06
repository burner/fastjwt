import vibe.d;

import fastjwt.jwt;
import stringbuffer;

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

// Get a new JWTToken
void login(HTTPServerRequest req, HTTPServerResponse res) {
	StringBuffer buf;
	encodeJWTToken(buf, algo, secret, "sub", 1337);
	res.writeBody(buf.getData());
}

// An example validator function that can be used as a template to custom
// validator function. See the router in the shared statis this for its usage.
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

	// Make sure that no reference of any StringBuffer do not escape, as their
	// stored data will be freed.
	StringBuffer header;
	StringBuffer payload;

	const rslt = decodeJWTToken(req.headers[authStr][bearer.length .. $],
			secret, algo, header, payload);

	if(rslt > 0) {
		res.writeBody("Your token was not OK");
		return;
	}

	//
	// Here you would parse payload into Json and see if you find the data
	// you were expecting
	//

	fun(req, res);
}

// If you JWTToken is not ok you cannot use this api.
void securedApi(HTTPServerRequest req, HTTPServerResponse res) {
	res.writeBody("Here is your secure api!");
}
