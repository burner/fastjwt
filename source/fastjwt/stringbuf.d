module fastjwt.stringbuf;

/** A super simple string buffer that will free its string if its gets out of
scope. To use it as a OutputRange use the value returned from the writer
method. getData will return a string that points to the data stored in the
StringBuffer. If the StringBuffer gets cleared up the string returned by
getData can no longer be used.
*/
struct StringBuffer {
	import core.memory : GC;
	enum stackLen = 512;
	char[stackLen] stack;
	char* overflow;
	size_t capacity = 512;
	size_t length;
	bool copied;

	~this() {
		if(this.overflow !is null) {
			GC.free(cast(void*)this.overflow);
		}
	}

	struct OutputRange {
		StringBuffer* buf;

		void put(const(char) c) @safe {
			this.buf.put(c);
		}

		void put(dchar c) @safe {
			this.buf.put(c);
		}

		void put(const(char)[] s) @safe {
			this.buf.put(s);
		}

		void put(string s) @safe {
			this.buf.put(s);
		}
	}

	OutputRange writer() {
		return OutputRange(&this);
	}

	private void putImpl(const(char) c) @trusted {
		if(this.length < stackLen) {
			this.stack[this.length++] = c;
		} else {
			if(this.length + 1 >= this.capacity || this.overflow is null) {
				this.grow();
				assert(this.overflow !is null);
			}
			this.overflow[this.length++] = c;
		}
	}

	private void grow() @trusted {
		this.capacity *= 2;
		this.overflow = cast(char*)GC.realloc(this.overflow, this.capacity);
		if(!this.copied) {
			for(size_t i = 0; i < stackLen; ++i) {
				this.overflow[i] = this.stack[i];
			}
			this.copied = true;
		}
	}

	void put(const(char) c) @safe {
		this.putImpl(c);
	}

	void put(dchar c) @safe {
		import std.utf : encode;
		char[4] encoded;
		size_t len = encode(encoded, c);
		this.put(encoded[0 .. len]);
	}

	void put(const(char)[] s) @trusted {
		if(s.length + this.length < stackLen) {
			for(size_t i = 0; i < s.length; ++i) {
				this.stack[this.length++] = s[i];
			}
		} else {
			while(s.length + this.length >= this.capacity 
					|| this.overflow is null) 
			{
				this.grow();
				assert(this.overflow !is null);
			}
			for(size_t i = 0; i < s.length; ++i) {
				this.overflow[this.length++] = s[i];
			}
		}
	}

	void put(string s) @safe {
		this.put(cast(const(char)[])s);
	}

	T getData(T = string)() {
		if(this.length >= stackLen) {
			return cast(T)this.overflow[0 .. this.length];
		} else {
			return cast(T)this.stack[0 .. this.length];
		}
	}
}

unittest {
	StringBuffer buf;
	buf.put('c');
	buf.put("c");

	assert(buf.getData() == "cc");

	for(int i = 0; i < 2048; ++i) {
		buf.put(cast(dchar)'c');
	}

	for(int i = 0; i < 2050; ++i) {
		assert(buf.getData()[i] == 'c');
	}
}

unittest {
	StringBuffer buf;
	buf.put('ö');
	assert(buf.getData() == "ö");

	buf.writer().put('ö');
	assert(buf.getData() == "öö");
}

unittest {
	StringBuffer buf;
	for(int i = 0; i < 1028; ++i) {
		buf.put('a');
	}

	auto s = buf.getData();
	for(int i = 0; i < s.length; ++i) {
		assert(s[i] == 'a');
	}
}

unittest {
	import std.range.primitives : isOutputRange;
	static assert(isOutputRange!(StringBuffer, char));
}

unittest {
	import std.format : formattedWrite;

	StringBuffer buf;
	formattedWrite(buf.writer(), "%d", 42);
	assert(buf.getData() == "42");
}

unittest {
	import vibe.data.json;
	import std.stdio;

	Json j1 = Json(["field2": Json(42)]);

	StringBuffer buf;
	auto w = buf.writer();
	writeJsonString(w, j1);
	assert(buf.getData() == "{\"field2\":42}");
}

unittest {
	string s = "0123456789";
	string l;
	for(int i = 0; i < 1026; ++i) {
		l ~= s;
	}

	StringBuffer buf;
	buf.put(l);

	string ls = buf.getData();
	for(int i = 0; i < ls.length; ++i) {
		assert(ls[i] == ('0' + (i % 10)));
	}
}
