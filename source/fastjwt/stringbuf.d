module fastjwt.stringbuf;

struct StringBuffer {
	import core.memory : GC;
	enum stackLen = 512;
	char[stackLen] stack;
	char* overflow;
	size_t capacity = 512;
	size_t length;
	bool copied;

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
		if(length < stackLen) {
			this.stack[this.length++] = c;
		} else {
			if(length >= capacity) {
				this.capacity *= 2;
				this.overflow = cast(char*)GC.realloc(this.overflow, this.capacity);
			}
			if(!this.copied) {
				for(size_t i = 0; i < stackLen; ++i) {
					this.overflow[i] = this.stack[i];
				}
				this.copied = true;
			}
			this.overflow[this.length++] = c;
		}
	}

	void put(const(char) c) @safe {
		this.putImpl(c);
	}

	void put(dchar c) @safe {
		import std.utf : encode;
		char[4] encoded;
		size_t len = encode(encoded, c);
		for(size_t i = 0; i < len; ++i) {
			this.put(encoded[i]);
		}
	}

	void put(const(char)[] s) @safe {
		for(size_t i = 0; i < s.length; ++i) {
			this.put(s[i]);
		}
	}

	void put(string s) @safe {
		for(size_t i = 0; i < s.length; ++i) {
			this.put(s[i]);
		}
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
