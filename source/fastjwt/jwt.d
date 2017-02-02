module fastjwt.jwt;

import vibe.data.json;

import fastjwt.stringbuf;

version(unittest) {
	import std.stdio;
}

enum JWTAlgorithm {
    NONE,
    HS256,
    HS384,
    HS512
}

void hash(ref StringBuffer buf, string data, string secret, JWTAlgorithm alg) {
	import std.digest.hmac;
	import std.digest.sha;
	import std.string : representation;
	import std.base64 : Base64Impl;

	alias URLSafeBase64 = Base64Impl!('-', '_', Base64.NoPadding);

	final switch(alg) {
		case JWTAlgorithm.HS256:
			auto signature = HMAC!SHA256(secret.representation);
			signature.put(data.representation);
			buf.put(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.HS384:
			auto signature = HMAC!SHA384(secret.representation);
			signature.put(data.representation);
			buf.put(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.HS512:
			auto signature = HMAC!SHA512(secret.representation);
			signature.put(data.representation);
			buf.put(URLSafeBase64.encode(signature.finish()));
			break;
		case JWTAlgorithm.NONE:
			break;
	}
}

import std.base64;

enum base64HeaderStrings = [
	Base64.encode(cast(ubyte[])"{\"alg\":\"none\",\"typ\":\"JWT\"}"),
	Base64.encode(cast(ubyte[])"{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
	Base64.encode(cast(ubyte[])"{\"alg\":\"HS384\",\"typ\":\"JWT\"}"),
	Base64.encode(cast(ubyte[])"{\"alg\":\"HS512\",\"typ\":\"JWT\"}")
];

void headerBase64(Out)(const JWTAlgorithm alg, ref Out output) {
	output.put(base64HeaderStrings[alg]);
}

unittest {
	import std.array : appender;

	StringBuffer buf;
	headerBase64(JWTAlgorithm.HS256, buf);
	writeln(buf.getData());
}

void payloadToBase64(Out)(ref Out output, const(Json) payload) {
	StringBuffer jsonString;
	auto w = jsonString.writer();
	writeJsonString(w, payload);
	//output.put(jsonString.getData());
	Base64.encode(jsonString.getData!(ubyte[])(), output);
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

	Base64.encode(jsonString.getData!(ubyte[])(), output.writer());
	//output.put(jsonString.getData());
}

unittest {
	Json j1 = Json(["field1": Json("foo"), "field2": Json(42), 
			"field3": Json(true)]
		);

	StringBuffer buf;
	payloadToBase64(buf, j1);

	StringBuffer buf2;
	payloadToBase64(buf2, "field1", "foo", "field2", 42, "field3", true);

	writefln("buf  %s\n", buf.getData());
	writefln("buf2 %s\n", buf2.getData());
}

void encodeJWTToken(Out, Args...)(ref Out output, JWTAlgorithm algo,
		string secret, Args args)
{
	StringBuffer tmp;
	headerBase64(algo, tmp);
	tmp.put('.');
	payloadToBase64(tmp, args);

	StringBuffer h;
	hash(h, tmp.getData(), secret, algo);

	output.put(tmp.getData());
	output.put('.');
	output.put(h.getData());
}

unittest {
    string secret = "supersecret";
	StringBuffer buf;
	encodeJWTToken(buf, JWTAlgorithm.HS256, secret, "id", 1337);
	writefln("%s", buf.getData());
}

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
		writefln("%s %s", h.getData(), encodedToken[dots[1] + 1 .. $]);
		return 3;
	}

	Base64.decode(encodedToken[0 .. dots[0]], header.writer());
	Base64.decode(encodedToken[dots[0] + 1 .. dots[1]], payload.writer());

	return 4;
}

unittest {
	import std.format : format;

    string secret = "supersecret";
	auto alg = JWTAlgorithm.HS256;

	for(int i = 0; i < 1024*128; ++i) {
		StringBuffer buf;
		encodeJWTToken(buf, alg, secret, "id", 1337);
		//writefln("%s", buf.getData());

		StringBuffer header;
		StringBuffer payload;

		int rslt = decodeJWTToken(buf.getData(), secret, alg, header, payload);
		assert(rslt == 4, format("%d", rslt));
		writeln(header.getData());
		writeln(payload.getData());
	}
}
