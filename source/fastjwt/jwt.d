module fastjwt.jwt;

import vibe.data.json;

//import fastjwt.stringbuf;
import stringbuffer;
import std.base64 : Base64Impl, Base64;

version(unittest) {
	import std.stdio;
}

enum JWTAlgorithm {
    NONE,
    HS256,
    HS384,
    HS512
}

alias URLSafeBase64 = Base64Impl!('-', '_', Base64.NoPadding);

void hash(ref StringBuffer buf, string data, string secret, JWTAlgorithm alg) {
	import std.digest.hmac;
	import std.digest.sha;
	import std.string : representation;

	final switch(alg) {
		case JWTAlgorithm.HS256:
			auto signature = HMAC!SHA256(secret.representation);
			signature.put(data.representation);
			buf.insertBack(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.HS384:
			auto signature = HMAC!SHA384(secret.representation);
			signature.put(data.representation);
			buf.insertBack(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.HS512:
			auto signature = HMAC!SHA512(secret.representation);
			signature.put(data.representation);
			buf.insertBack(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.NONE:
			break;
	}
}

const base64HeaderStrings = [
	URLSafeBase64.encode(cast(ubyte[])"{\"alg\":\"none\",\"typ\":\"JWT\"}"),
	URLSafeBase64.encode(cast(ubyte[])"{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
	URLSafeBase64.encode(cast(ubyte[])"{\"alg\":\"HS384\",\"typ\":\"JWT\"}"),
	URLSafeBase64.encode(cast(ubyte[])"{\"alg\":\"HS512\",\"typ\":\"JWT\"}")
];

void headerBase64(Out)(const JWTAlgorithm alg, ref Out output) {
	output.insertBack(base64HeaderStrings[alg]);
}

unittest {
	import std.array : appender;

	StringBuffer buf;
	headerBase64(JWTAlgorithm.HS256, buf);
}

void payloadToBase64(Out)(ref Out output, const(Json) payload) {
	StringBuffer jsonString;
	auto w = jsonString.writer();
	writeJsonString(w, payload);
	Base64.encode(jsonString.getData!(ubyte[])(), output.writer());
}

void payloadToBase64(Out,Args...)(ref Out output, Args args)
		if(args.length > 0 && args.length % 2 == 0 && !is(args[0] == Json))
{
	import std.format : formattedWrite;
	void impl(Out,T,S,Args...)(ref Out loutput, bool first, T t, S s, Args args)
   	{
		import std.traits : isIntegral, isFloatingPoint, isSomeString;
		if(!first) {
			loutput.put(',');
		}
		static if(isIntegral!S) {
			formattedWrite(loutput, "\"%s\":%d", t, s);
		} else static if(isFloatingPoint!S) {
			formattedWrite(loutput, "\"%s\":%f", t, s);
		} else static if(isSomeString!S) {
			formattedWrite(loutput, "\"%s\":\"%s\"", t, s);
		} else static if(is(S == bool)) {
			formattedWrite(loutput, "\"%s\":%s", t, s);
		}

		static if(args.length > 0) {
			impl(loutput, false, args);
		}
	}

	StringBuffer jsonString;
	auto w = jsonString.writer();
	w.put("{");
	impl(w, true, args);
	w.put("}");
	URLSafeBase64.encode(jsonString.getData!(ubyte[])(), output.writer());
}

unittest {
	Json j1 = Json(["field1": Json("foo"), "field2": Json(42),
			"field3": Json(true)]
		);

	StringBuffer buf;
	payloadToBase64(buf, j1);

	StringBuffer buf2;
	payloadToBase64(buf2, "field1", "foo", "field2", 42, "field3", true);

	auto a = Json(buf.getData());
	auto b = Json(buf.getData());

	assert(a == b);
}

/** Encode values into a JWTToken string that gets stored into the output
parameter.

Params:
	output = The Output Range to store the JWTToken string
	algo = The algorithm to encode the JWTToken with
	secret = The secret to use to encode the JWTToken with
	args = The values to encode into the JWTToken. Args must be come in pairs
		of two. A string and a value.
*/
void encodeJWTToken(Out, Args...)(ref Out output, JWTAlgorithm algo,
		string secret, Args args)
{
	StringBuffer tmp;
	headerBase64(algo, tmp);
	tmp.insertBack('.');
	payloadToBase64(tmp, args);

	StringBuffer h;
	hash(h, tmp.getData(), secret, algo);

	output.insertBack(tmp.getData());
	output.insertBack('.');
	output.insertBack(h.getData());
}

///
void encodeJWTToken(Out)(ref Out output, JWTAlgorithm algo,
		string secret, const(Json) args)
{
	StringBuffer tmp;
	headerBase64(algo, tmp);
	tmp.insertBack('.');
	payloadToBase64(tmp, args);

	StringBuffer h;
	hash(h, tmp.getData(), secret, algo);

	output.insertBack(tmp.getData());
	output.insertBack('.');
	output.insertBack(h.getData());
}

///
unittest {
	foreach(alg; [JWTAlgorithm.HS384, JWTAlgorithm.HS256, JWTAlgorithm.HS512]) {
    	string secret = "supersecret";
		StringBuffer buf;
		encodeJWTToken(buf, alg, secret, "id", 1337);

		StringBuffer buf2;
		Json j = Json(["id" : Json(1337)]);
		encodeJWTToken(buf2, alg, secret, j);
	}
}

/** This function decodes a JWTToken.
Params:
	encodedToken = The Token
	secret = The secret used to encode the JWTToken
	algo = The algoirthm used to encode the JWTToken
	header = The buffer to store the decoded Header of the JWTToken
	payload = The buffer to store the decoded Payload of the JWTToken

Returns: 0 if everything is ok, everything means the token is not ok
*/
int decodeJWTToken(string encodedToken, string secret,
		JWTAlgorithm algo, ref StringBuffer header, ref StringBuffer payload)
{
	import std.algorithm.iteration : splitter;
	import std.string : indexOf;

	ptrdiff_t[2] dots;
	dots[0] = encodedToken.indexOf('.');

	if(dots[0] == -1) {
		return 1;
	}

	dots[1] = encodedToken.indexOf('.', dots[0] + 1);

	if(dots[1] == -1) {
		return 2;
	}

	StringBuffer h;
	hash(h, encodedToken[0 .. dots[1]], secret, algo);

	if(h.getData() != encodedToken[dots[1] + 1 .. $]) {
		return 3;
	}

	URLSafeBase64.decode(encodedToken[0 .. dots[0]], header.writer());
	URLSafeBase64.decode(encodedToken[dots[0] + 1 .. dots[1]], payload.writer());

	return 0;
}

///
unittest {
	import std.format : format;

    string secret = "supersecret";
	auto alg = JWTAlgorithm.HS256;

	StringBuffer buf;
	encodeJWTToken(buf, alg, secret, "sub", 1337);

	StringBuffer header;
	StringBuffer payload;

	int rslt = decodeJWTToken(buf.getData(), secret, alg, header, payload);
	assert(rslt == 0, format("%d", rslt));
}

unittest {
	auto s = ["asldjasldj","aslkdjas.asdlj","asdlj..alsdj"];
	auto secret = "secret";
	auto alg = JWTAlgorithm.HS256;

	for(int i = 0; i < s.length; ++i) {
		StringBuffer header;
		StringBuffer payload;

		auto rslt = decodeJWTToken(s[i], secret, alg, header, payload);
		assert(rslt == i + 1);
	}
}

unittest {
	import std.format : format;

    string secret = "supersecret";
	auto alg = JWTAlgorithm.HS256;

	for(int i = 0; i < 1024*2; ++i) {
		StringBuffer buf;
		encodeJWTToken(buf, alg, secret, "id", 1337);

		StringBuffer header;
		StringBuffer payload;

		int rslt = decodeJWTToken(buf.getData(), secret, alg, header, payload);
		assert(rslt == 0, format("%d", rslt));
	}
}
