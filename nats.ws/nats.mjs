// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.

// This is a specialised implementation of a System module loader.

"use strict";

// @ts-nocheck
/* eslint-disable */
let System, __instantiate;
(() => {
  const r = new Map();

  System = {
    register(id, d, f) {
      r.set(id, { d, f, exp: {} });
    },
  };
  async function dI(mid, src) {
    let id = mid.replace(/\.\w+$/i, "");
    if (id.includes("./")) {
      const [o, ...ia] = id.split("/").reverse(),
        [, ...sa] = src.split("/").reverse(),
        oa = [o];
      let s = 0,
        i;
      while ((i = ia.shift())) {
        if (i === "..") s++;
        else if (i === ".") break;
        else oa.push(i);
      }
      if (s < sa.length) oa.push(...sa.slice(s));
      id = oa.reverse().join("/");
    }
    return r.has(id) ? gExpA(id) : import(mid);
  }

  function gC(id, main) {
    return {
      id,
      import: (m) => dI(m, id),
      meta: { url: id, main },
    };
  }

  function gE(exp) {
    return (id, v) => {
      v = typeof id === "string" ? { [id]: v } : id;
      for (const [id, value] of Object.entries(v)) {
        Object.defineProperty(exp, id, {
          value,
          writable: true,
          enumerable: true,
        });
      }
    };
  }

  function rF(main) {
    for (const [id, m] of r.entries()) {
      const { f, exp } = m;
      const { execute: e, setters: s } = f(gE(exp), gC(id, id === main));
      delete m.f;
      m.e = e;
      m.s = s;
    }
  }

  async function gExpA(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](await gExpA(d[i]));
      const r = e();
      if (r) await r;
    }
    return m.exp;
  }

  function gExp(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](gExp(d[i]));
      e();
    }
    return m.exp;
  }
  __instantiate = (m, a) => {
    System = __instantiate = undefined;
    rF(m);
    return a ? gExpA(m) : gExp(m);
  };
})();

System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", [], function (exports_1, context_1) {
    "use strict";
    var ErrorCode, Messages, NatsError;
    var __moduleName = context_1 && context_1.id;
    return {
        setters: [],
        execute: function () {
            (function (ErrorCode) {
                ErrorCode["API_ERROR"] = "BAD API";
                ErrorCode["BAD_AUTHENTICATION"] = "BAD_AUTHENTICATION";
                ErrorCode["BAD_CREDS"] = "BAD_CREDS";
                ErrorCode["BAD_HEADER"] = "BAD_HEADER";
                ErrorCode["BAD_JSON"] = "BAD_JSON";
                ErrorCode["BAD_PAYLOAD"] = "BAD_PAYLOAD";
                ErrorCode["BAD_SUBJECT"] = "BAD_SUBJECT";
                ErrorCode["CANCELLED"] = "CANCELLED";
                ErrorCode["CONNECTION_CLOSED"] = "CONNECTION_CLOSED";
                ErrorCode["CONNECTION_DRAINING"] = "CONNECTION_DRAINING";
                ErrorCode["CONNECTION_REFUSED"] = "CONNECTION_REFUSED";
                ErrorCode["CONNECTION_TIMEOUT"] = "CONNECTION_TIMEOUT";
                ErrorCode["DISCONNECT"] = "DISCONNECT";
                ErrorCode["INVALID_OPTION"] = "INVALID_OPTION";
                ErrorCode["INVALID_PAYLOAD_TYPE"] = "INVALID_PAYLOAD";
                ErrorCode["MAX_PAYLOAD_EXCEEDED"] = "MAX_PAYLOAD_EXCEEDED";
                ErrorCode["NOT_FUNC"] = "NOT_FUNC";
                ErrorCode["REQUEST_ERROR"] = "REQUEST_ERROR";
                ErrorCode["SERVER_OPTION_NA"] = "SERVER_OPT_NA";
                ErrorCode["SUB_CLOSED"] = "SUB_CLOSED";
                ErrorCode["SUB_DRAINING"] = "SUB_DRAINING";
                ErrorCode["TIMEOUT"] = "TIMEOUT";
                ErrorCode["TLS"] = "TLS";
                ErrorCode["UNKNOWN"] = "UNKNOWN_ERROR";
                ErrorCode["WSS_REQUIRED"] = "WSS_REQUIRED";
                ErrorCode["AUTHORIZATION_VIOLATION"] = "AUTHORIZATION_VIOLATION";
                ErrorCode["NATS_PROTOCOL_ERR"] = "NATS_PROTOCOL_ERR";
                ErrorCode["PERMISSIONS_VIOLATION"] = "PERMISSIONS_VIOLATION";
            })(ErrorCode || (ErrorCode = {}));
            exports_1("ErrorCode", ErrorCode);
            Messages = class Messages {
                constructor() {
                    this.messages = new Map();
                    this.messages.set(ErrorCode.INVALID_PAYLOAD_TYPE, "Invalid payload type - payloads can be 'binary', 'string', or 'json'");
                    this.messages.set(ErrorCode.BAD_JSON, "Bad JSON");
                    this.messages.set(ErrorCode.WSS_REQUIRED, "TLS is required, therefore a secure websocket connection is also required");
                }
                static getMessage(s) {
                    return Messages.messages.getMessage(s);
                }
                getMessage(s) {
                    return this.messages.get(s) || s;
                }
            };
            exports_1("Messages", Messages);
            Messages.messages = new Messages();
            NatsError = class NatsError extends Error {
                constructor(message, code, chainedError) {
                    super(message);
                    this.name = "NatsError";
                    this.message = message;
                    this.code = code;
                    this.chainedError = chainedError;
                }
                static errorForCode(code, chainedError) {
                    let m = Messages.getMessage(code);
                    return new NatsError(m, code, chainedError);
                }
            };
            exports_1("NatsError", NatsError);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/headers", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_2, context_2) {
    "use strict";
    var error_ts_1, encoders_ts_1, MsgHdrsImpl;
    var __moduleName = context_2 && context_2.id;
    function headers() {
        return new MsgHdrsImpl();
    }
    exports_2("headers", headers);
    return {
        setters: [
            function (error_ts_1_1) {
                error_ts_1 = error_ts_1_1;
            },
            function (encoders_ts_1_1) {
                encoders_ts_1 = encoders_ts_1_1;
            }
        ],
        execute: function () {
            MsgHdrsImpl = class MsgHdrsImpl {
                constructor() {
                    this.headers = new Map();
                }
                [Symbol.iterator]() {
                    return this.headers.entries();
                }
                size() {
                    let count = 0;
                    for (const [_, v] of this.headers.entries()) {
                        count += v.length;
                    }
                    return count;
                }
                equals(mh) {
                    if (mh && this.headers.size === mh.headers.size &&
                        this.error === mh.error) {
                        for (const [k, v] of this.headers) {
                            const a = mh.values(k);
                            if (v.length !== a.length) {
                                return false;
                            }
                            const vv = [...v].sort();
                            const aa = [...a].sort();
                            for (let i = 0; i < vv.length; i++) {
                                if (vv[i] !== aa[i]) {
                                    return false;
                                }
                            }
                            return true;
                        }
                    }
                    return false;
                }
                static decode(a) {
                    const mh = new MsgHdrsImpl();
                    const s = encoders_ts_1.TD.decode(a);
                    const lines = s.split(MsgHdrsImpl.CRLF);
                    const h = lines[0];
                    if (h !== MsgHdrsImpl.HEADER) {
                        const str = h.replace(MsgHdrsImpl.HEADER, "");
                        mh.error = parseInt(str, 10);
                    }
                    else {
                        lines.slice(1).map((s) => {
                            if (s) {
                                const idx = s.indexOf(MsgHdrsImpl.SEP);
                                const k = s.slice(0, idx);
                                const v = s.slice(idx + 1);
                                mh.append(k, v);
                            }
                        });
                    }
                    return mh;
                }
                toString() {
                    if (this.headers.size === 0) {
                        return "";
                    }
                    let s = MsgHdrsImpl.HEADER;
                    for (const [k, v] of this.headers) {
                        for (let i = 0; i < v.length; i++) {
                            s = `${s}\r\n${k}:${v[i]}`;
                        }
                    }
                    return `${s}\r\n\r\n`;
                }
                encode() {
                    return encoders_ts_1.TE.encode(this.toString());
                }
                static canonicalMIMEHeaderKey(k) {
                    const a = 97;
                    const A = 65;
                    const Z = 90;
                    const z = 122;
                    const dash = 45;
                    const colon = 58;
                    const start = 33;
                    const end = 126;
                    const toLower = a - A;
                    let upper = true;
                    const buf = new Array(k.length);
                    for (let i = 0; i < k.length; i++) {
                        let c = k.charCodeAt(i);
                        if (c === colon || c < start || c > end) {
                            throw new error_ts_1.NatsError(`'${k[i]}' is not a valid character for a header key`, error_ts_1.ErrorCode.BAD_HEADER);
                        }
                        if (upper && a <= c && c <= z) {
                            c -= toLower;
                        }
                        else if (!upper && A <= c && c <= Z) {
                            c += toLower;
                        }
                        buf[i] = c;
                        upper = c == dash;
                    }
                    return String.fromCharCode(...buf);
                }
                static validHeaderValue(k) {
                    const inv = /[\r\n]/;
                    if (inv.test(k)) {
                        throw new error_ts_1.NatsError("invalid header value - \\r and \\n are not allowed.", error_ts_1.ErrorCode.BAD_HEADER);
                    }
                    return k.trim();
                }
                get(k) {
                    const key = MsgHdrsImpl.canonicalMIMEHeaderKey(k);
                    const a = this.headers.get(key);
                    return a ? a[0] : "";
                }
                has(k) {
                    return this.get(k) !== "";
                }
                set(k, v) {
                    const key = MsgHdrsImpl.canonicalMIMEHeaderKey(k);
                    const value = MsgHdrsImpl.validHeaderValue(v);
                    this.headers.set(key, [value]);
                }
                append(k, v) {
                    const key = MsgHdrsImpl.canonicalMIMEHeaderKey(k);
                    const value = MsgHdrsImpl.validHeaderValue(v);
                    let a = this.headers.get(key);
                    if (!a) {
                        a = [];
                        this.headers.set(key, a);
                    }
                    a.push(value);
                }
                values(k) {
                    const key = MsgHdrsImpl.canonicalMIMEHeaderKey(k);
                    return this.headers.get(key) || [];
                }
                delete(k) {
                    const key = MsgHdrsImpl.canonicalMIMEHeaderKey(k);
                    this.headers.delete(key);
                }
            };
            exports_2("MsgHdrsImpl", MsgHdrsImpl);
            MsgHdrsImpl.CRLF = "\r\n";
            MsgHdrsImpl.SEP = ":";
            MsgHdrsImpl.HEADER = "NATS/1.0";
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/helper", [], function (exports_3, context_3) {
    "use strict";
    var helper;
    var __moduleName = context_3 && context_3.id;
    function setEd25519Helper(lib) {
        helper = lib;
    }
    exports_3("setEd25519Helper", setEd25519Helper);
    function getEd25519Helper() {
        return helper;
    }
    exports_3("getEd25519Helper", getEd25519Helper);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", [], function (exports_4, context_4) {
    "use strict";
    var __moduleName = context_4 && context_4.id;
    function ByteArray(n) {
        return new Uint8Array(n);
    }
    exports_4("ByteArray", ByteArray);
    function HalfArray(n) {
        return new Uint16Array(n);
    }
    exports_4("HalfArray", HalfArray);
    function WordArray(n) {
        return new Uint32Array(n);
    }
    exports_4("WordArray", WordArray);
    function IntArray(n) {
        return new Int32Array(n);
    }
    exports_4("IntArray", IntArray);
    function NumArray(n) {
        return new Float64Array(n);
    }
    exports_4("NumArray", NumArray);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/validate", [], function (exports_5, context_5) {
    "use strict";
    var __moduleName = context_5 && context_5.id;
    function validateBase64(s) {
        if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
            throw new TypeError('invalid base64 string');
        }
    }
    exports_5("validateBase64", validateBase64);
    function validateHex(s) {
        if (!/^(?:[A-Fa-f0-9]{2})+$/.test(s)) {
            throw new TypeError('invalid hex string');
        }
    }
    exports_5("validateHex", validateHex);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/chiefbiiko/base64/master/base", [], function (exports_6, context_6) {
    "use strict";
    var __moduleName = context_6 && context_6.id;
    function getLengths(b64) {
        const len = b64.length;
        let validLen = b64.indexOf("=");
        if (validLen === -1) {
            validLen = len;
        }
        const placeHoldersLen = validLen === len ? 0 : 4 - (validLen % 4);
        return [validLen, placeHoldersLen];
    }
    function init(lookup, revLookup, urlsafe = false) {
        function _byteLength(validLen, placeHoldersLen) {
            return Math.floor(((validLen + placeHoldersLen) * 3) / 4 - placeHoldersLen);
        }
        function tripletToBase64(num) {
            return (lookup[(num >> 18) & 0x3f] +
                lookup[(num >> 12) & 0x3f] +
                lookup[(num >> 6) & 0x3f] +
                lookup[num & 0x3f]);
        }
        function encodeChunk(buf, start, end) {
            const out = new Array((end - start) / 3);
            for (let i = start, curTriplet = 0; i < end; i += 3) {
                out[curTriplet++] = tripletToBase64((buf[i] << 16) + (buf[i + 1] << 8) + buf[i + 2]);
            }
            return out.join("");
        }
        return {
            byteLength(b64) {
                return _byteLength.apply(null, getLengths(b64));
            },
            toUint8Array(b64) {
                const [validLen, placeHoldersLen] = getLengths(b64);
                const buf = new Uint8Array(_byteLength(validLen, placeHoldersLen));
                const len = placeHoldersLen ? validLen - 4 : validLen;
                let tmp;
                let curByte = 0;
                let i;
                for (i = 0; i < len; i += 4) {
                    tmp = (revLookup[b64.charCodeAt(i)] << 18) |
                        (revLookup[b64.charCodeAt(i + 1)] << 12) |
                        (revLookup[b64.charCodeAt(i + 2)] << 6) |
                        revLookup[b64.charCodeAt(i + 3)];
                    buf[curByte++] = (tmp >> 16) & 0xff;
                    buf[curByte++] = (tmp >> 8) & 0xff;
                    buf[curByte++] = tmp & 0xff;
                }
                if (placeHoldersLen === 2) {
                    tmp = (revLookup[b64.charCodeAt(i)] << 2) |
                        (revLookup[b64.charCodeAt(i + 1)] >> 4);
                    buf[curByte++] = tmp & 0xff;
                }
                else if (placeHoldersLen === 1) {
                    tmp = (revLookup[b64.charCodeAt(i)] << 10) |
                        (revLookup[b64.charCodeAt(i + 1)] << 4) |
                        (revLookup[b64.charCodeAt(i + 2)] >> 2);
                    buf[curByte++] = (tmp >> 8) & 0xff;
                    buf[curByte++] = tmp & 0xff;
                }
                return buf;
            },
            fromUint8Array(buf) {
                const maxChunkLength = 16383;
                const len = buf.length;
                const extraBytes = len % 3;
                const len2 = len - extraBytes;
                const parts = new Array(Math.ceil(len2 / maxChunkLength) + (extraBytes ? 1 : 0));
                let curChunk = 0;
                let chunkEnd;
                for (let i = 0; i < len2; i += maxChunkLength) {
                    chunkEnd = i + maxChunkLength;
                    parts[curChunk++] = encodeChunk(buf, i, chunkEnd > len2 ? len2 : chunkEnd);
                }
                let tmp;
                if (extraBytes === 1) {
                    tmp = buf[len2];
                    parts[curChunk] = lookup[tmp >> 2] + lookup[(tmp << 4) & 0x3f];
                    if (!urlsafe)
                        parts[curChunk] += "==";
                }
                else if (extraBytes === 2) {
                    tmp = (buf[len2] << 8) | (buf[len2 + 1] & 0xff);
                    parts[curChunk] = lookup[tmp >> 10] +
                        lookup[(tmp >> 4) & 0x3f] +
                        lookup[(tmp << 2) & 0x3f];
                    if (!urlsafe)
                        parts[curChunk] += "=";
                }
                return parts.join("");
            },
        };
    }
    exports_6("init", init);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/chiefbiiko/base64/master/mod", ["https://raw.githubusercontent.com/chiefbiiko/base64/master/base"], function (exports_7, context_7) {
    "use strict";
    var base_ts_1, lookup, revLookup, code, _a, byteLength, toUint8Array, fromUint8Array;
    var __moduleName = context_7 && context_7.id;
    return {
        setters: [
            function (base_ts_1_1) {
                base_ts_1 = base_ts_1_1;
            }
        ],
        execute: function () {
            lookup = [];
            revLookup = [];
            code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (let i = 0, l = code.length; i < l; ++i) {
                lookup[i] = code[i];
                revLookup[code.charCodeAt(i)] = i;
            }
            revLookup["-".charCodeAt(0)] = 62;
            revLookup["_".charCodeAt(0)] = 63;
            _a = base_ts_1.init(lookup, revLookup), exports_7("byteLength", byteLength = _a.byteLength), exports_7("toUint8Array", toUint8Array = _a.toUint8Array), exports_7("fromUint8Array", fromUint8Array = _a.fromUint8Array);
        }
    };
});
System.register("https://deno.land/std@0.52.0/encoding/hex", [], function (exports_8, context_8) {
    "use strict";
    var hextable;
    var __moduleName = context_8 && context_8.id;
    function errInvalidByte(byte) {
        return new Error("encoding/hex: invalid byte: " +
            new TextDecoder().decode(new Uint8Array([byte])));
    }
    exports_8("errInvalidByte", errInvalidByte);
    function errLength() {
        return new Error("encoding/hex: odd length hex string");
    }
    exports_8("errLength", errLength);
    function fromHexChar(byte) {
        switch (true) {
            case 48 <= byte && byte <= 57:
                return [byte - 48, true];
            case 97 <= byte && byte <= 102:
                return [byte - 97 + 10, true];
            case 65 <= byte && byte <= 70:
                return [byte - 65 + 10, true];
        }
        return [0, false];
    }
    function encodedLen(n) {
        return n * 2;
    }
    exports_8("encodedLen", encodedLen);
    function encode(dst, src) {
        const srcLength = encodedLen(src.length);
        if (dst.length !== srcLength) {
            throw new Error("Out of index.");
        }
        for (let i = 0; i < src.length; i++) {
            const v = src[i];
            dst[i * 2] = hextable[v >> 4];
            dst[i * 2 + 1] = hextable[v & 0x0f];
        }
        return srcLength;
    }
    exports_8("encode", encode);
    function encodeToString(src) {
        const dest = new Uint8Array(encodedLen(src.length));
        encode(dest, src);
        return new TextDecoder().decode(dest);
    }
    exports_8("encodeToString", encodeToString);
    function decode(dst, src) {
        let i = 0;
        for (; i < Math.floor(src.length / 2); i++) {
            const [a, aOK] = fromHexChar(src[i * 2]);
            if (!aOK) {
                return [i, errInvalidByte(src[i * 2])];
            }
            const [b, bOK] = fromHexChar(src[i * 2 + 1]);
            if (!bOK) {
                return [i, errInvalidByte(src[i * 2 + 1])];
            }
            dst[i] = (a << 4) | b;
        }
        if (src.length % 2 == 1) {
            const [, ok] = fromHexChar(src[i * 2]);
            if (!ok) {
                return [i, errInvalidByte(src[i * 2])];
            }
            return [i, errLength()];
        }
        return [i, undefined];
    }
    exports_8("decode", decode);
    function decodedLen(x) {
        return Math.floor(x / 2);
    }
    exports_8("decodedLen", decodedLen);
    function decodeString(s) {
        const src = new TextEncoder().encode(s);
        const [n, err] = decode(src, src);
        if (err) {
            throw err;
        }
        return src.slice(0, n);
    }
    exports_8("decodeString", decodeString);
    return {
        setters: [],
        execute: function () {
            hextable = new TextEncoder().encode("0123456789abcdef");
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/server/convert", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/validate", "https://raw.githubusercontent.com/chiefbiiko/base64/master/mod", "https://deno.land/std@0.52.0/encoding/hex"], function (exports_9, context_9) {
    "use strict";
    var validate_ts_1, base64, hex_ts_1, encoder, decoder;
    var __moduleName = context_9 && context_9.id;
    function encodeUTF8(a) {
        return decoder.decode(a);
    }
    exports_9("encodeUTF8", encodeUTF8);
    function decodeUTF8(s) {
        return encoder.encode(s);
    }
    exports_9("decodeUTF8", decodeUTF8);
    function encodeBase64(a) {
        return base64.fromUint8Array(a);
    }
    exports_9("encodeBase64", encodeBase64);
    function decodeBase64(s) {
        validate_ts_1.validateBase64(s);
        return base64.toUint8Array(s);
    }
    exports_9("decodeBase64", decodeBase64);
    function encodeHex(a) {
        return hex_ts_1.encodeToString(a);
    }
    exports_9("encodeHex", encodeHex);
    function decodeHex(s) {
        validate_ts_1.validateHex(s);
        return hex_ts_1.decodeString(s);
    }
    exports_9("decodeHex", decodeHex);
    return {
        setters: [
            function (validate_ts_1_1) {
                validate_ts_1 = validate_ts_1_1;
            },
            function (base64_1) {
                base64 = base64_1;
            },
            function (hex_ts_1_1) {
                hex_ts_1 = hex_ts_1_1;
            }
        ],
        execute: function () {
            encoder = new TextEncoder();
            decoder = new TextDecoder();
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/convert", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/server/convert"], function (exports_10, context_10) {
    "use strict";
    var __moduleName = context_10 && context_10.id;
    function exportStar_1(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default") exports[n] = m[n];
        }
        exports_10(exports);
    }
    return {
        setters: [
            function (convert_ts_1_1) {
                exportStar_1(convert_ts_1_1);
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/salsa20", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_11, context_11) {
    "use strict";
    var array_ts_1, _sigma;
    var __moduleName = context_11 && context_11.id;
    function _salsa20(o, p, k, c) {
        const j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24, j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24, j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24, j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24, j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24, j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24, j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24, j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24, j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24, j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24, j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24, j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24, j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24, j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24, j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24, j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;
        let x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
        for (let i = 0; i < 20; i += 2) {
            u = x0 + x12 | 0;
            x4 ^= u << 7 | u >>> (32 - 7);
            u = x4 + x0 | 0;
            x8 ^= u << 9 | u >>> (32 - 9);
            u = x8 + x4 | 0;
            x12 ^= u << 13 | u >>> (32 - 13);
            u = x12 + x8 | 0;
            x0 ^= u << 18 | u >>> (32 - 18);
            u = x5 + x1 | 0;
            x9 ^= u << 7 | u >>> (32 - 7);
            u = x9 + x5 | 0;
            x13 ^= u << 9 | u >>> (32 - 9);
            u = x13 + x9 | 0;
            x1 ^= u << 13 | u >>> (32 - 13);
            u = x1 + x13 | 0;
            x5 ^= u << 18 | u >>> (32 - 18);
            u = x10 + x6 | 0;
            x14 ^= u << 7 | u >>> (32 - 7);
            u = x14 + x10 | 0;
            x2 ^= u << 9 | u >>> (32 - 9);
            u = x2 + x14 | 0;
            x6 ^= u << 13 | u >>> (32 - 13);
            u = x6 + x2 | 0;
            x10 ^= u << 18 | u >>> (32 - 18);
            u = x15 + x11 | 0;
            x3 ^= u << 7 | u >>> (32 - 7);
            u = x3 + x15 | 0;
            x7 ^= u << 9 | u >>> (32 - 9);
            u = x7 + x3 | 0;
            x11 ^= u << 13 | u >>> (32 - 13);
            u = x11 + x7 | 0;
            x15 ^= u << 18 | u >>> (32 - 18);
            u = x0 + x3 | 0;
            x1 ^= u << 7 | u >>> (32 - 7);
            u = x1 + x0 | 0;
            x2 ^= u << 9 | u >>> (32 - 9);
            u = x2 + x1 | 0;
            x3 ^= u << 13 | u >>> (32 - 13);
            u = x3 + x2 | 0;
            x0 ^= u << 18 | u >>> (32 - 18);
            u = x5 + x4 | 0;
            x6 ^= u << 7 | u >>> (32 - 7);
            u = x6 + x5 | 0;
            x7 ^= u << 9 | u >>> (32 - 9);
            u = x7 + x6 | 0;
            x4 ^= u << 13 | u >>> (32 - 13);
            u = x4 + x7 | 0;
            x5 ^= u << 18 | u >>> (32 - 18);
            u = x10 + x9 | 0;
            x11 ^= u << 7 | u >>> (32 - 7);
            u = x11 + x10 | 0;
            x8 ^= u << 9 | u >>> (32 - 9);
            u = x8 + x11 | 0;
            x9 ^= u << 13 | u >>> (32 - 13);
            u = x9 + x8 | 0;
            x10 ^= u << 18 | u >>> (32 - 18);
            u = x15 + x14 | 0;
            x12 ^= u << 7 | u >>> (32 - 7);
            u = x12 + x15 | 0;
            x13 ^= u << 9 | u >>> (32 - 9);
            u = x13 + x12 | 0;
            x14 ^= u << 13 | u >>> (32 - 13);
            u = x14 + x13 | 0;
            x15 ^= u << 18 | u >>> (32 - 18);
        }
        x0 = x0 + j0 | 0;
        x1 = x1 + j1 | 0;
        x2 = x2 + j2 | 0;
        x3 = x3 + j3 | 0;
        x4 = x4 + j4 | 0;
        x5 = x5 + j5 | 0;
        x6 = x6 + j6 | 0;
        x7 = x7 + j7 | 0;
        x8 = x8 + j8 | 0;
        x9 = x9 + j9 | 0;
        x10 = x10 + j10 | 0;
        x11 = x11 + j11 | 0;
        x12 = x12 + j12 | 0;
        x13 = x13 + j13 | 0;
        x14 = x14 + j14 | 0;
        x15 = x15 + j15 | 0;
        o[0] = x0 >>> 0 & 0xff;
        o[1] = x0 >>> 8 & 0xff;
        o[2] = x0 >>> 16 & 0xff;
        o[3] = x0 >>> 24 & 0xff;
        o[4] = x1 >>> 0 & 0xff;
        o[5] = x1 >>> 8 & 0xff;
        o[6] = x1 >>> 16 & 0xff;
        o[7] = x1 >>> 24 & 0xff;
        o[8] = x2 >>> 0 & 0xff;
        o[9] = x2 >>> 8 & 0xff;
        o[10] = x2 >>> 16 & 0xff;
        o[11] = x2 >>> 24 & 0xff;
        o[12] = x3 >>> 0 & 0xff;
        o[13] = x3 >>> 8 & 0xff;
        o[14] = x3 >>> 16 & 0xff;
        o[15] = x3 >>> 24 & 0xff;
        o[16] = x4 >>> 0 & 0xff;
        o[17] = x4 >>> 8 & 0xff;
        o[18] = x4 >>> 16 & 0xff;
        o[19] = x4 >>> 24 & 0xff;
        o[20] = x5 >>> 0 & 0xff;
        o[21] = x5 >>> 8 & 0xff;
        o[22] = x5 >>> 16 & 0xff;
        o[23] = x5 >>> 24 & 0xff;
        o[24] = x6 >>> 0 & 0xff;
        o[25] = x6 >>> 8 & 0xff;
        o[26] = x6 >>> 16 & 0xff;
        o[27] = x6 >>> 24 & 0xff;
        o[28] = x7 >>> 0 & 0xff;
        o[29] = x7 >>> 8 & 0xff;
        o[30] = x7 >>> 16 & 0xff;
        o[31] = x7 >>> 24 & 0xff;
        o[32] = x8 >>> 0 & 0xff;
        o[33] = x8 >>> 8 & 0xff;
        o[34] = x8 >>> 16 & 0xff;
        o[35] = x8 >>> 24 & 0xff;
        o[36] = x9 >>> 0 & 0xff;
        o[37] = x9 >>> 8 & 0xff;
        o[38] = x9 >>> 16 & 0xff;
        o[39] = x9 >>> 24 & 0xff;
        o[40] = x10 >>> 0 & 0xff;
        o[41] = x10 >>> 8 & 0xff;
        o[42] = x10 >>> 16 & 0xff;
        o[43] = x10 >>> 24 & 0xff;
        o[44] = x11 >>> 0 & 0xff;
        o[45] = x11 >>> 8 & 0xff;
        o[46] = x11 >>> 16 & 0xff;
        o[47] = x11 >>> 24 & 0xff;
        o[48] = x12 >>> 0 & 0xff;
        o[49] = x12 >>> 8 & 0xff;
        o[50] = x12 >>> 16 & 0xff;
        o[51] = x12 >>> 24 & 0xff;
        o[52] = x13 >>> 0 & 0xff;
        o[53] = x13 >>> 8 & 0xff;
        o[54] = x13 >>> 16 & 0xff;
        o[55] = x13 >>> 24 & 0xff;
        o[56] = x14 >>> 0 & 0xff;
        o[57] = x14 >>> 8 & 0xff;
        o[58] = x14 >>> 16 & 0xff;
        o[59] = x14 >>> 24 & 0xff;
        o[60] = x15 >>> 0 & 0xff;
        o[61] = x15 >>> 8 & 0xff;
        o[62] = x15 >>> 16 & 0xff;
        o[63] = x15 >>> 24 & 0xff;
    }
    exports_11("_salsa20", _salsa20);
    function _hsalsa20(o, p, k, c) {
        const j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24, j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24, j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24, j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24, j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24, j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24, j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24, j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24, j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24, j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24, j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24, j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24, j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24, j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24, j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24, j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;
        let x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
        for (let i = 0; i < 20; i += 2) {
            u = x0 + x12 | 0;
            x4 ^= u << 7 | u >>> (32 - 7);
            u = x4 + x0 | 0;
            x8 ^= u << 9 | u >>> (32 - 9);
            u = x8 + x4 | 0;
            x12 ^= u << 13 | u >>> (32 - 13);
            u = x12 + x8 | 0;
            x0 ^= u << 18 | u >>> (32 - 18);
            u = x5 + x1 | 0;
            x9 ^= u << 7 | u >>> (32 - 7);
            u = x9 + x5 | 0;
            x13 ^= u << 9 | u >>> (32 - 9);
            u = x13 + x9 | 0;
            x1 ^= u << 13 | u >>> (32 - 13);
            u = x1 + x13 | 0;
            x5 ^= u << 18 | u >>> (32 - 18);
            u = x10 + x6 | 0;
            x14 ^= u << 7 | u >>> (32 - 7);
            u = x14 + x10 | 0;
            x2 ^= u << 9 | u >>> (32 - 9);
            u = x2 + x14 | 0;
            x6 ^= u << 13 | u >>> (32 - 13);
            u = x6 + x2 | 0;
            x10 ^= u << 18 | u >>> (32 - 18);
            u = x15 + x11 | 0;
            x3 ^= u << 7 | u >>> (32 - 7);
            u = x3 + x15 | 0;
            x7 ^= u << 9 | u >>> (32 - 9);
            u = x7 + x3 | 0;
            x11 ^= u << 13 | u >>> (32 - 13);
            u = x11 + x7 | 0;
            x15 ^= u << 18 | u >>> (32 - 18);
            u = x0 + x3 | 0;
            x1 ^= u << 7 | u >>> (32 - 7);
            u = x1 + x0 | 0;
            x2 ^= u << 9 | u >>> (32 - 9);
            u = x2 + x1 | 0;
            x3 ^= u << 13 | u >>> (32 - 13);
            u = x3 + x2 | 0;
            x0 ^= u << 18 | u >>> (32 - 18);
            u = x5 + x4 | 0;
            x6 ^= u << 7 | u >>> (32 - 7);
            u = x6 + x5 | 0;
            x7 ^= u << 9 | u >>> (32 - 9);
            u = x7 + x6 | 0;
            x4 ^= u << 13 | u >>> (32 - 13);
            u = x4 + x7 | 0;
            x5 ^= u << 18 | u >>> (32 - 18);
            u = x10 + x9 | 0;
            x11 ^= u << 7 | u >>> (32 - 7);
            u = x11 + x10 | 0;
            x8 ^= u << 9 | u >>> (32 - 9);
            u = x8 + x11 | 0;
            x9 ^= u << 13 | u >>> (32 - 13);
            u = x9 + x8 | 0;
            x10 ^= u << 18 | u >>> (32 - 18);
            u = x15 + x14 | 0;
            x12 ^= u << 7 | u >>> (32 - 7);
            u = x12 + x15 | 0;
            x13 ^= u << 9 | u >>> (32 - 9);
            u = x13 + x12 | 0;
            x14 ^= u << 13 | u >>> (32 - 13);
            u = x14 + x13 | 0;
            x15 ^= u << 18 | u >>> (32 - 18);
        }
        o[0] = x0 >>> 0 & 0xff;
        o[1] = x0 >>> 8 & 0xff;
        o[2] = x0 >>> 16 & 0xff;
        o[3] = x0 >>> 24 & 0xff;
        o[4] = x5 >>> 0 & 0xff;
        o[5] = x5 >>> 8 & 0xff;
        o[6] = x5 >>> 16 & 0xff;
        o[7] = x5 >>> 24 & 0xff;
        o[8] = x10 >>> 0 & 0xff;
        o[9] = x10 >>> 8 & 0xff;
        o[10] = x10 >>> 16 & 0xff;
        o[11] = x10 >>> 24 & 0xff;
        o[12] = x15 >>> 0 & 0xff;
        o[13] = x15 >>> 8 & 0xff;
        o[14] = x15 >>> 16 & 0xff;
        o[15] = x15 >>> 24 & 0xff;
        o[16] = x6 >>> 0 & 0xff;
        o[17] = x6 >>> 8 & 0xff;
        o[18] = x6 >>> 16 & 0xff;
        o[19] = x6 >>> 24 & 0xff;
        o[20] = x7 >>> 0 & 0xff;
        o[21] = x7 >>> 8 & 0xff;
        o[22] = x7 >>> 16 & 0xff;
        o[23] = x7 >>> 24 & 0xff;
        o[24] = x8 >>> 0 & 0xff;
        o[25] = x8 >>> 8 & 0xff;
        o[26] = x8 >>> 16 & 0xff;
        o[27] = x8 >>> 24 & 0xff;
        o[28] = x9 >>> 0 & 0xff;
        o[29] = x9 >>> 8 & 0xff;
        o[30] = x9 >>> 16 & 0xff;
        o[31] = x9 >>> 24 & 0xff;
    }
    exports_11("_hsalsa20", _hsalsa20);
    function _stream_salsa20_xor(c, cpos, m, mpos, b, n, k) {
        const z = array_ts_1.ByteArray(16), x = array_ts_1.ByteArray(64);
        let u, i;
        for (i = 0; i < 16; i++)
            z[i] = 0;
        for (i = 0; i < 8; i++)
            z[i] = n[i];
        while (b >= 64) {
            _salsa20(x, z, k, _sigma);
            for (i = 0; i < 64; i++)
                c[cpos + i] = m[mpos + i] ^ x[i];
            u = 1;
            for (i = 8; i < 16; i++) {
                u = u + (z[i] & 0xff) | 0;
                z[i] = u & 0xff;
                u >>>= 8;
            }
            b -= 64;
            cpos += 64;
            mpos += 64;
        }
        if (b > 0) {
            _salsa20(x, z, k, _sigma);
            for (i = 0; i < b; i++)
                c[cpos + i] = m[mpos + i] ^ x[i];
        }
        return 0;
    }
    function _stream_salsa20(c, cpos, b, n, k) {
        const z = array_ts_1.ByteArray(16), x = array_ts_1.ByteArray(64);
        let u, i;
        for (i = 0; i < 16; i++)
            z[i] = 0;
        for (i = 0; i < 8; i++)
            z[i] = n[i];
        while (b >= 64) {
            _salsa20(x, z, k, _sigma);
            for (i = 0; i < 64; i++)
                c[cpos + i] = x[i];
            u = 1;
            for (i = 8; i < 16; i++) {
                u = u + (z[i] & 0xff) | 0;
                z[i] = u & 0xff;
                u >>>= 8;
            }
            b -= 64;
            cpos += 64;
        }
        if (b > 0) {
            _salsa20(x, z, k, _sigma);
            for (i = 0; i < b; i++)
                c[cpos + i] = x[i];
        }
        return 0;
    }
    function _stream(c, cpos, d, n, k) {
        const s = array_ts_1.ByteArray(32), sn = array_ts_1.ByteArray(8);
        _hsalsa20(s, n, k, _sigma);
        for (let i = 0; i < 8; i++)
            sn[i] = n[i + 16];
        return _stream_salsa20(c, cpos, d, sn, s);
    }
    exports_11("_stream", _stream);
    function _stream_xor(c, cpos, m, mpos, d, n, k) {
        const s = array_ts_1.ByteArray(32), sn = array_ts_1.ByteArray(8);
        _hsalsa20(s, n, k, _sigma);
        for (let i = 0; i < 8; i++)
            sn[i] = n[i + 16];
        return _stream_salsa20_xor(c, cpos, m, mpos, d, sn, s);
    }
    exports_11("_stream_xor", _stream_xor);
    return {
        setters: [
            function (array_ts_1_1) {
                array_ts_1 = array_ts_1_1;
            }
        ],
        execute: function () {
            exports_11("_sigma", _sigma = array_ts_1.ByteArray([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]));
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/poly1305", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_12, context_12) {
    "use strict";
    var array_ts_2;
    var __moduleName = context_12 && context_12.id;
    function poly1305_init(key) {
        const r = array_ts_2.HalfArray(10);
        const pad = array_ts_2.HalfArray(8);
        let t0, t1, t2, t3, t4, t5, t6, t7;
        t0 = key[0] & 0xff | (key[1] & 0xff) << 8;
        r[0] = (t0) & 0x1fff;
        t1 = key[2] & 0xff | (key[3] & 0xff) << 8;
        r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
        t2 = key[4] & 0xff | (key[5] & 0xff) << 8;
        r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
        t3 = key[6] & 0xff | (key[7] & 0xff) << 8;
        r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
        t4 = key[8] & 0xff | (key[9] & 0xff) << 8;
        r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
        r[5] = ((t4 >>> 1)) & 0x1ffe;
        t5 = key[10] & 0xff | (key[11] & 0xff) << 8;
        r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
        t6 = key[12] & 0xff | (key[13] & 0xff) << 8;
        r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
        t7 = key[14] & 0xff | (key[15] & 0xff) << 8;
        r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
        r[9] = ((t7 >>> 5)) & 0x007f;
        pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
        pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
        pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
        pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
        pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
        pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
        pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
        pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
        return {
            buffer: array_ts_2.ByteArray(16),
            r,
            h: array_ts_2.HalfArray(10),
            pad,
            leftover: 0,
            fin: 0,
        };
    }
    exports_12("poly1305_init", poly1305_init);
    function poly1305_blocks(self, m, mpos, bytes) {
        const hibit = self.fin ? 0 : (1 << 11);
        let t0, t1, t2, t3, t4, t5, t6, t7, c;
        let d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
        const { h, r } = self;
        let h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
        const r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4], r5 = r[5], r6 = r[6], r7 = r[7], r8 = r[8], r9 = r[9];
        while (bytes >= 16) {
            t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8;
            h0 += (t0) & 0x1fff;
            t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8;
            h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
            t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8;
            h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
            t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8;
            h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
            t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8;
            h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
            h5 += ((t4 >>> 1)) & 0x1fff;
            t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8;
            h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
            t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8;
            h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
            t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8;
            h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
            h9 += ((t7 >>> 5)) | hibit;
            c = 0;
            d0 = c;
            d0 += h0 * r0;
            d0 += h1 * (5 * r9);
            d0 += h2 * (5 * r8);
            d0 += h3 * (5 * r7);
            d0 += h4 * (5 * r6);
            c = (d0 >>> 13);
            d0 &= 0x1fff;
            d0 += h5 * (5 * r5);
            d0 += h6 * (5 * r4);
            d0 += h7 * (5 * r3);
            d0 += h8 * (5 * r2);
            d0 += h9 * (5 * r1);
            c += (d0 >>> 13);
            d0 &= 0x1fff;
            d1 = c;
            d1 += h0 * r1;
            d1 += h1 * r0;
            d1 += h2 * (5 * r9);
            d1 += h3 * (5 * r8);
            d1 += h4 * (5 * r7);
            c = (d1 >>> 13);
            d1 &= 0x1fff;
            d1 += h5 * (5 * r6);
            d1 += h6 * (5 * r5);
            d1 += h7 * (5 * r4);
            d1 += h8 * (5 * r3);
            d1 += h9 * (5 * r2);
            c += (d1 >>> 13);
            d1 &= 0x1fff;
            d2 = c;
            d2 += h0 * r2;
            d2 += h1 * r1;
            d2 += h2 * r0;
            d2 += h3 * (5 * r9);
            d2 += h4 * (5 * r8);
            c = (d2 >>> 13);
            d2 &= 0x1fff;
            d2 += h5 * (5 * r7);
            d2 += h6 * (5 * r6);
            d2 += h7 * (5 * r5);
            d2 += h8 * (5 * r4);
            d2 += h9 * (5 * r3);
            c += (d2 >>> 13);
            d2 &= 0x1fff;
            d3 = c;
            d3 += h0 * r3;
            d3 += h1 * r2;
            d3 += h2 * r1;
            d3 += h3 * r0;
            d3 += h4 * (5 * r9);
            c = (d3 >>> 13);
            d3 &= 0x1fff;
            d3 += h5 * (5 * r8);
            d3 += h6 * (5 * r7);
            d3 += h7 * (5 * r6);
            d3 += h8 * (5 * r5);
            d3 += h9 * (5 * r4);
            c += (d3 >>> 13);
            d3 &= 0x1fff;
            d4 = c;
            d4 += h0 * r4;
            d4 += h1 * r3;
            d4 += h2 * r2;
            d4 += h3 * r1;
            d4 += h4 * r0;
            c = (d4 >>> 13);
            d4 &= 0x1fff;
            d4 += h5 * (5 * r9);
            d4 += h6 * (5 * r8);
            d4 += h7 * (5 * r7);
            d4 += h8 * (5 * r6);
            d4 += h9 * (5 * r5);
            c += (d4 >>> 13);
            d4 &= 0x1fff;
            d5 = c;
            d5 += h0 * r5;
            d5 += h1 * r4;
            d5 += h2 * r3;
            d5 += h3 * r2;
            d5 += h4 * r1;
            c = (d5 >>> 13);
            d5 &= 0x1fff;
            d5 += h5 * r0;
            d5 += h6 * (5 * r9);
            d5 += h7 * (5 * r8);
            d5 += h8 * (5 * r7);
            d5 += h9 * (5 * r6);
            c += (d5 >>> 13);
            d5 &= 0x1fff;
            d6 = c;
            d6 += h0 * r6;
            d6 += h1 * r5;
            d6 += h2 * r4;
            d6 += h3 * r3;
            d6 += h4 * r2;
            c = (d6 >>> 13);
            d6 &= 0x1fff;
            d6 += h5 * r1;
            d6 += h6 * r0;
            d6 += h7 * (5 * r9);
            d6 += h8 * (5 * r8);
            d6 += h9 * (5 * r7);
            c += (d6 >>> 13);
            d6 &= 0x1fff;
            d7 = c;
            d7 += h0 * r7;
            d7 += h1 * r6;
            d7 += h2 * r5;
            d7 += h3 * r4;
            d7 += h4 * r3;
            c = (d7 >>> 13);
            d7 &= 0x1fff;
            d7 += h5 * r2;
            d7 += h6 * r1;
            d7 += h7 * r0;
            d7 += h8 * (5 * r9);
            d7 += h9 * (5 * r8);
            c += (d7 >>> 13);
            d7 &= 0x1fff;
            d8 = c;
            d8 += h0 * r8;
            d8 += h1 * r7;
            d8 += h2 * r6;
            d8 += h3 * r5;
            d8 += h4 * r4;
            c = (d8 >>> 13);
            d8 &= 0x1fff;
            d8 += h5 * r3;
            d8 += h6 * r2;
            d8 += h7 * r1;
            d8 += h8 * r0;
            d8 += h9 * (5 * r9);
            c += (d8 >>> 13);
            d8 &= 0x1fff;
            d9 = c;
            d9 += h0 * r9;
            d9 += h1 * r8;
            d9 += h2 * r7;
            d9 += h3 * r6;
            d9 += h4 * r5;
            c = (d9 >>> 13);
            d9 &= 0x1fff;
            d9 += h5 * r4;
            d9 += h6 * r3;
            d9 += h7 * r2;
            d9 += h8 * r1;
            d9 += h9 * r0;
            c += (d9 >>> 13);
            d9 &= 0x1fff;
            c = (((c << 2) + c)) | 0;
            c = (c + d0) | 0;
            d0 = c & 0x1fff;
            c = (c >>> 13);
            d1 += c;
            h0 = d0;
            h1 = d1;
            h2 = d2;
            h3 = d3;
            h4 = d4;
            h5 = d5;
            h6 = d6;
            h7 = d7;
            h8 = d8;
            h9 = d9;
            mpos += 16;
            bytes -= 16;
        }
        h[0] = h0;
        h[1] = h1;
        h[2] = h2;
        h[3] = h3;
        h[4] = h4;
        h[5] = h5;
        h[6] = h6;
        h[7] = h7;
        h[8] = h8;
        h[9] = h9;
    }
    exports_12("poly1305_blocks", poly1305_blocks);
    function poly1305_finish(self, mac, macpos) {
        const g = array_ts_2.HalfArray(10);
        let c, mask, f, i;
        const { buffer, h, pad, leftover } = self;
        if (leftover) {
            i = leftover;
            buffer[i++] = 1;
            for (; i < 16; i++)
                buffer[i] = 0;
            self.fin = 1;
            poly1305_blocks(self, buffer, 0, 16);
        }
        c = h[1] >>> 13;
        h[1] &= 0x1fff;
        for (i = 2; i < 10; i++) {
            h[i] += c;
            c = h[i] >>> 13;
            h[i] &= 0x1fff;
        }
        h[0] += (c * 5);
        c = h[0] >>> 13;
        h[0] &= 0x1fff;
        h[1] += c;
        c = h[1] >>> 13;
        h[1] &= 0x1fff;
        h[2] += c;
        g[0] = h[0] + 5;
        c = g[0] >>> 13;
        g[0] &= 0x1fff;
        for (i = 1; i < 10; i++) {
            g[i] = h[i] + c;
            c = g[i] >>> 13;
            g[i] &= 0x1fff;
        }
        g[9] -= (1 << 13);
        mask = (c ^ 1) - 1;
        for (i = 0; i < 10; i++)
            g[i] &= mask;
        mask = ~mask;
        for (i = 0; i < 10; i++)
            h[i] = (h[i] & mask) | g[i];
        h[0] = ((h[0]) | (h[1] << 13)) & 0xffff;
        h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
        h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
        h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
        h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
        h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
        h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
        h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;
        f = h[0] + pad[0];
        h[0] = f & 0xffff;
        for (i = 1; i < 8; i++) {
            f = (((h[i] + pad[i]) | 0) + (f >>> 16)) | 0;
            h[i] = f & 0xffff;
        }
        mac[macpos + 0] = (h[0] >>> 0) & 0xff;
        mac[macpos + 1] = (h[0] >>> 8) & 0xff;
        mac[macpos + 2] = (h[1] >>> 0) & 0xff;
        mac[macpos + 3] = (h[1] >>> 8) & 0xff;
        mac[macpos + 4] = (h[2] >>> 0) & 0xff;
        mac[macpos + 5] = (h[2] >>> 8) & 0xff;
        mac[macpos + 6] = (h[3] >>> 0) & 0xff;
        mac[macpos + 7] = (h[3] >>> 8) & 0xff;
        mac[macpos + 8] = (h[4] >>> 0) & 0xff;
        mac[macpos + 9] = (h[4] >>> 8) & 0xff;
        mac[macpos + 10] = (h[5] >>> 0) & 0xff;
        mac[macpos + 11] = (h[5] >>> 8) & 0xff;
        mac[macpos + 12] = (h[6] >>> 0) & 0xff;
        mac[macpos + 13] = (h[6] >>> 8) & 0xff;
        mac[macpos + 14] = (h[7] >>> 0) & 0xff;
        mac[macpos + 15] = (h[7] >>> 8) & 0xff;
    }
    exports_12("poly1305_finish", poly1305_finish);
    function poly1305_update(self, m, mpos, bytes) {
        let i, want;
        const { buffer } = self;
        if (self.leftover) {
            want = (16 - self.leftover);
            if (want > bytes)
                want = bytes;
            for (i = 0; i < want; i++)
                buffer[self.leftover + i] = m[mpos + i];
            bytes -= want;
            mpos += want;
            self.leftover += want;
            if (self.leftover < 16)
                return;
            poly1305_blocks(self, buffer, 0, 16);
            self.leftover = 0;
        }
        if (bytes >= 16) {
            want = bytes - (bytes % 16);
            poly1305_blocks(self, m, mpos, want);
            mpos += want;
            bytes -= want;
        }
        if (bytes) {
            for (i = 0; i < bytes; i++)
                buffer[self.leftover + i] = m[mpos + i];
            self.leftover += bytes;
        }
    }
    exports_12("poly1305_update", poly1305_update);
    return {
        setters: [
            function (array_ts_2_1) {
                array_ts_2 = array_ts_2_1;
            }
        ],
        execute: function () {
            ;
            ;
            ;
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/secretbox", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/verify", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/salsa20", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/poly1305", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_13, context_13) {
    "use strict";
    var array_ts_3, verify_ts_1, salsa20_ts_1, poly1305_ts_1, check_ts_1;
    var __moduleName = context_13 && context_13.id;
    function secretbox(msg, nonce, key) {
        check_ts_1.checkArrayTypes(msg, nonce, key);
        check_ts_1.checkLengths(key, nonce);
        const m = array_ts_3.ByteArray(32 + msg.length);
        const c = array_ts_3.ByteArray(m.length);
        for (let i = 0; i < msg.length; i++)
            m[i + 32] = msg[i];
        _secretbox(c, m, m.length, nonce, key);
        return c.subarray(16);
    }
    exports_13("secretbox", secretbox);
    function secretbox_open(box, nonce, key) {
        check_ts_1.checkArrayTypes(box, nonce, key);
        check_ts_1.checkLengths(key, nonce);
        const c = array_ts_3.ByteArray(16 + box.length);
        const m = array_ts_3.ByteArray(c.length);
        for (let i = 0; i < box.length; i++)
            c[i + 16] = box[i];
        if (c.length < 32 || _secretbox_open(m, c, c.length, nonce, key) !== 0)
            return;
        return m.subarray(32);
    }
    exports_13("secretbox_open", secretbox_open);
    function _secretbox(c, m, d, n, k) {
        if (d < 32)
            return -1;
        salsa20_ts_1._stream_xor(c, 0, m, 0, d, n, k);
        _onetimeauth(c, 16, c, 32, d - 32, c);
        for (let i = 0; i < 16; i++)
            c[i] = 0;
        return 0;
    }
    function _secretbox_open(m, c, d, n, k) {
        const x = array_ts_3.ByteArray(32);
        if (d < 32)
            return -1;
        salsa20_ts_1._stream(x, 0, 32, n, k);
        if (_onetimeauth_verify(c, 16, c, 32, d - 32, x) !== 0)
            return -1;
        salsa20_ts_1._stream_xor(m, 0, c, 0, d, n, k);
        for (let i = 0; i < 32; i++)
            m[i] = 0;
        return 0;
    }
    function _onetimeauth(out, outpos, m, mpos, n, k) {
        const s = poly1305_ts_1.poly1305_init(k);
        poly1305_ts_1.poly1305_update(s, m, mpos, n);
        poly1305_ts_1.poly1305_finish(s, out, outpos);
        return 0;
    }
    exports_13("_onetimeauth", _onetimeauth);
    function _onetimeauth_verify(h, hpos, m, mpos, n, k) {
        const x = array_ts_3.ByteArray(16);
        _onetimeauth(x, 0, m, mpos, n, k);
        return verify_ts_1._verify_16(h, hpos, x, 0);
    }
    return {
        setters: [
            function (array_ts_3_1) {
                array_ts_3 = array_ts_3_1;
            },
            function (verify_ts_1_1) {
                verify_ts_1 = verify_ts_1_1;
            },
            function (salsa20_ts_1_1) {
                salsa20_ts_1 = salsa20_ts_1_1;
            },
            function (poly1305_ts_1_1) {
                poly1305_ts_1 = poly1305_ts_1_1;
            },
            function (check_ts_1_1) {
                check_ts_1 = check_ts_1_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/core", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_14, context_14) {
    "use strict";
    var array_ts_4, _0, _9, gf0, gf1, _121665, D, D2, X, Y, I;
    var __moduleName = context_14 && context_14.id;
    function gf(init) {
        const r = array_ts_4.NumArray(16);
        if (init)
            for (let i = 0; i < init.length; i++)
                r[i] = init[i];
        return r;
    }
    exports_14("gf", gf);
    function A(o, a, b) {
        for (let i = 0; i < 16; i++)
            o[i] = a[i] + b[i];
    }
    exports_14("A", A);
    function Z(o, a, b) {
        for (let i = 0; i < 16; i++)
            o[i] = a[i] - b[i];
    }
    exports_14("Z", Z);
    function M(o, a, b) {
        let v, c, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0, t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0, t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0, b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5], b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9], b10 = b[10], b11 = b[11], b12 = b[12], b13 = b[13], b14 = b[14], b15 = b[15];
        v = a[0];
        t0 += v * b0;
        t1 += v * b1;
        t2 += v * b2;
        t3 += v * b3;
        t4 += v * b4;
        t5 += v * b5;
        t6 += v * b6;
        t7 += v * b7;
        t8 += v * b8;
        t9 += v * b9;
        t10 += v * b10;
        t11 += v * b11;
        t12 += v * b12;
        t13 += v * b13;
        t14 += v * b14;
        t15 += v * b15;
        v = a[1];
        t1 += v * b0;
        t2 += v * b1;
        t3 += v * b2;
        t4 += v * b3;
        t5 += v * b4;
        t6 += v * b5;
        t7 += v * b6;
        t8 += v * b7;
        t9 += v * b8;
        t10 += v * b9;
        t11 += v * b10;
        t12 += v * b11;
        t13 += v * b12;
        t14 += v * b13;
        t15 += v * b14;
        t16 += v * b15;
        v = a[2];
        t2 += v * b0;
        t3 += v * b1;
        t4 += v * b2;
        t5 += v * b3;
        t6 += v * b4;
        t7 += v * b5;
        t8 += v * b6;
        t9 += v * b7;
        t10 += v * b8;
        t11 += v * b9;
        t12 += v * b10;
        t13 += v * b11;
        t14 += v * b12;
        t15 += v * b13;
        t16 += v * b14;
        t17 += v * b15;
        v = a[3];
        t3 += v * b0;
        t4 += v * b1;
        t5 += v * b2;
        t6 += v * b3;
        t7 += v * b4;
        t8 += v * b5;
        t9 += v * b6;
        t10 += v * b7;
        t11 += v * b8;
        t12 += v * b9;
        t13 += v * b10;
        t14 += v * b11;
        t15 += v * b12;
        t16 += v * b13;
        t17 += v * b14;
        t18 += v * b15;
        v = a[4];
        t4 += v * b0;
        t5 += v * b1;
        t6 += v * b2;
        t7 += v * b3;
        t8 += v * b4;
        t9 += v * b5;
        t10 += v * b6;
        t11 += v * b7;
        t12 += v * b8;
        t13 += v * b9;
        t14 += v * b10;
        t15 += v * b11;
        t16 += v * b12;
        t17 += v * b13;
        t18 += v * b14;
        t19 += v * b15;
        v = a[5];
        t5 += v * b0;
        t6 += v * b1;
        t7 += v * b2;
        t8 += v * b3;
        t9 += v * b4;
        t10 += v * b5;
        t11 += v * b6;
        t12 += v * b7;
        t13 += v * b8;
        t14 += v * b9;
        t15 += v * b10;
        t16 += v * b11;
        t17 += v * b12;
        t18 += v * b13;
        t19 += v * b14;
        t20 += v * b15;
        v = a[6];
        t6 += v * b0;
        t7 += v * b1;
        t8 += v * b2;
        t9 += v * b3;
        t10 += v * b4;
        t11 += v * b5;
        t12 += v * b6;
        t13 += v * b7;
        t14 += v * b8;
        t15 += v * b9;
        t16 += v * b10;
        t17 += v * b11;
        t18 += v * b12;
        t19 += v * b13;
        t20 += v * b14;
        t21 += v * b15;
        v = a[7];
        t7 += v * b0;
        t8 += v * b1;
        t9 += v * b2;
        t10 += v * b3;
        t11 += v * b4;
        t12 += v * b5;
        t13 += v * b6;
        t14 += v * b7;
        t15 += v * b8;
        t16 += v * b9;
        t17 += v * b10;
        t18 += v * b11;
        t19 += v * b12;
        t20 += v * b13;
        t21 += v * b14;
        t22 += v * b15;
        v = a[8];
        t8 += v * b0;
        t9 += v * b1;
        t10 += v * b2;
        t11 += v * b3;
        t12 += v * b4;
        t13 += v * b5;
        t14 += v * b6;
        t15 += v * b7;
        t16 += v * b8;
        t17 += v * b9;
        t18 += v * b10;
        t19 += v * b11;
        t20 += v * b12;
        t21 += v * b13;
        t22 += v * b14;
        t23 += v * b15;
        v = a[9];
        t9 += v * b0;
        t10 += v * b1;
        t11 += v * b2;
        t12 += v * b3;
        t13 += v * b4;
        t14 += v * b5;
        t15 += v * b6;
        t16 += v * b7;
        t17 += v * b8;
        t18 += v * b9;
        t19 += v * b10;
        t20 += v * b11;
        t21 += v * b12;
        t22 += v * b13;
        t23 += v * b14;
        t24 += v * b15;
        v = a[10];
        t10 += v * b0;
        t11 += v * b1;
        t12 += v * b2;
        t13 += v * b3;
        t14 += v * b4;
        t15 += v * b5;
        t16 += v * b6;
        t17 += v * b7;
        t18 += v * b8;
        t19 += v * b9;
        t20 += v * b10;
        t21 += v * b11;
        t22 += v * b12;
        t23 += v * b13;
        t24 += v * b14;
        t25 += v * b15;
        v = a[11];
        t11 += v * b0;
        t12 += v * b1;
        t13 += v * b2;
        t14 += v * b3;
        t15 += v * b4;
        t16 += v * b5;
        t17 += v * b6;
        t18 += v * b7;
        t19 += v * b8;
        t20 += v * b9;
        t21 += v * b10;
        t22 += v * b11;
        t23 += v * b12;
        t24 += v * b13;
        t25 += v * b14;
        t26 += v * b15;
        v = a[12];
        t12 += v * b0;
        t13 += v * b1;
        t14 += v * b2;
        t15 += v * b3;
        t16 += v * b4;
        t17 += v * b5;
        t18 += v * b6;
        t19 += v * b7;
        t20 += v * b8;
        t21 += v * b9;
        t22 += v * b10;
        t23 += v * b11;
        t24 += v * b12;
        t25 += v * b13;
        t26 += v * b14;
        t27 += v * b15;
        v = a[13];
        t13 += v * b0;
        t14 += v * b1;
        t15 += v * b2;
        t16 += v * b3;
        t17 += v * b4;
        t18 += v * b5;
        t19 += v * b6;
        t20 += v * b7;
        t21 += v * b8;
        t22 += v * b9;
        t23 += v * b10;
        t24 += v * b11;
        t25 += v * b12;
        t26 += v * b13;
        t27 += v * b14;
        t28 += v * b15;
        v = a[14];
        t14 += v * b0;
        t15 += v * b1;
        t16 += v * b2;
        t17 += v * b3;
        t18 += v * b4;
        t19 += v * b5;
        t20 += v * b6;
        t21 += v * b7;
        t22 += v * b8;
        t23 += v * b9;
        t24 += v * b10;
        t25 += v * b11;
        t26 += v * b12;
        t27 += v * b13;
        t28 += v * b14;
        t29 += v * b15;
        v = a[15];
        t15 += v * b0;
        t16 += v * b1;
        t17 += v * b2;
        t18 += v * b3;
        t19 += v * b4;
        t20 += v * b5;
        t21 += v * b6;
        t22 += v * b7;
        t23 += v * b8;
        t24 += v * b9;
        t25 += v * b10;
        t26 += v * b11;
        t27 += v * b12;
        t28 += v * b13;
        t29 += v * b14;
        t30 += v * b15;
        t0 += 38 * t16;
        t1 += 38 * t17;
        t2 += 38 * t18;
        t3 += 38 * t19;
        t4 += 38 * t20;
        t5 += 38 * t21;
        t6 += 38 * t22;
        t7 += 38 * t23;
        t8 += 38 * t24;
        t9 += 38 * t25;
        t10 += 38 * t26;
        t11 += 38 * t27;
        t12 += 38 * t28;
        t13 += 38 * t29;
        t14 += 38 * t30;
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor(v / 65536);
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor(v / 65536);
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor(v / 65536);
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor(v / 65536);
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor(v / 65536);
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor(v / 65536);
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor(v / 65536);
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor(v / 65536);
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor(v / 65536);
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor(v / 65536);
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor(v / 65536);
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor(v / 65536);
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor(v / 65536);
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor(v / 65536);
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor(v / 65536);
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor(v / 65536);
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * (c - 1);
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor(v / 65536);
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor(v / 65536);
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor(v / 65536);
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor(v / 65536);
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor(v / 65536);
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor(v / 65536);
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor(v / 65536);
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor(v / 65536);
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor(v / 65536);
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor(v / 65536);
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor(v / 65536);
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor(v / 65536);
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor(v / 65536);
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor(v / 65536);
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor(v / 65536);
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor(v / 65536);
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * (c - 1);
        o[0] = t0;
        o[1] = t1;
        o[2] = t2;
        o[3] = t3;
        o[4] = t4;
        o[5] = t5;
        o[6] = t6;
        o[7] = t7;
        o[8] = t8;
        o[9] = t9;
        o[10] = t10;
        o[11] = t11;
        o[12] = t12;
        o[13] = t13;
        o[14] = t14;
        o[15] = t15;
    }
    exports_14("M", M);
    function S(o, a) {
        M(o, a, a);
    }
    exports_14("S", S);
    return {
        setters: [
            function (array_ts_4_1) {
                array_ts_4 = array_ts_4_1;
            }
        ],
        execute: function () {
            exports_14("_0", _0 = array_ts_4.ByteArray(16));
            exports_14("_9", _9 = array_ts_4.ByteArray(32));
            _9[0] = 9;
            exports_14("gf0", gf0 = gf());
            exports_14("gf1", gf1 = gf([1]));
            exports_14("_121665", _121665 = gf([0xdb41, 1]));
            exports_14("D", D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]));
            exports_14("D2", D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]));
            exports_14("X", X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]));
            exports_14("Y", Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]));
            exports_14("I", I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]));
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/random", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_15, context_15) {
    "use strict";
    var array_ts_5;
    var __moduleName = context_15 && context_15.id;
    function randomBytes(n) {
        let b = array_ts_5.ByteArray(n);
        window.crypto.getRandomValues(b);
        return b;
    }
    exports_15("randomBytes", randomBytes);
    return {
        setters: [
            function (array_ts_5_1) {
                array_ts_5 = array_ts_5_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/curve25519", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/verify", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/core"], function (exports_16, context_16) {
    "use strict";
    var array_ts_6, verify_ts_2, core_ts_1;
    var __moduleName = context_16 && context_16.id;
    function set25519(r, a) {
        for (let i = 0; i < 16; i++)
            r[i] = a[i] | 0;
    }
    exports_16("set25519", set25519);
    function car25519(o) {
        let i, v, c = 1;
        for (i = 0; i < 16; i++) {
            v = o[i] + c + 65535;
            c = Math.floor(v / 65536);
            o[i] = v - c * 65536;
        }
        o[0] += c - 1 + 37 * (c - 1);
    }
    function sel25519(p, q, b) {
        let t, c = ~(b - 1);
        for (let i = 0; i < 16; i++) {
            t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }
    exports_16("sel25519", sel25519);
    function pack25519(o, n) {
        const m = core_ts_1.gf(), t = core_ts_1.gf();
        let i, j, b;
        for (i = 0; i < 16; i++)
            t[i] = n[i];
        car25519(t);
        car25519(t);
        car25519(t);
        for (j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            sel25519(t, m, 1 - b);
        }
        for (i = 0; i < 16; i++) {
            o[2 * i] = t[i] & 0xff;
            o[2 * i + 1] = t[i] >> 8;
        }
    }
    exports_16("pack25519", pack25519);
    function neq25519(a, b) {
        const c = array_ts_6.ByteArray(32), d = array_ts_6.ByteArray(32);
        pack25519(c, a);
        pack25519(d, b);
        return verify_ts_2._verify_32(c, 0, d, 0);
    }
    exports_16("neq25519", neq25519);
    function par25519(a) {
        const d = array_ts_6.ByteArray(32);
        pack25519(d, a);
        return d[0] & 1;
    }
    exports_16("par25519", par25519);
    function unpack25519(o, n) {
        for (let i = 0; i < 16; i++)
            o[i] = n[2 * i] + (n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }
    exports_16("unpack25519", unpack25519);
    function inv25519(o, i) {
        const c = core_ts_1.gf();
        let a;
        for (a = 0; a < 16; a++)
            c[a] = i[a];
        for (a = 253; a >= 0; a--) {
            core_ts_1.S(c, c);
            if (a !== 2 && a !== 4)
                core_ts_1.M(c, c, i);
        }
        for (a = 0; a < 16; a++)
            o[a] = c[a];
    }
    exports_16("inv25519", inv25519);
    return {
        setters: [
            function (array_ts_6_1) {
                array_ts_6 = array_ts_6_1;
            },
            function (verify_ts_2_1) {
                verify_ts_2 = verify_ts_2_1;
            },
            function (core_ts_1_1) {
                core_ts_1 = core_ts_1_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/scalarmult", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/core", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/curve25519", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_17, context_17) {
    "use strict";
    var array_ts_7, core_ts_2, curve25519_ts_1, check_ts_2;
    var __moduleName = context_17 && context_17.id;
    function scalarMult(n, p) {
        check_ts_2.checkArrayTypes(n, p);
        if (n.length !== 32)
            throw new Error('bad n size');
        if (p.length !== 32)
            throw new Error('bad p size');
        const q = array_ts_7.ByteArray(32);
        _scalarMult(q, n, p);
        return q;
    }
    exports_17("scalarMult", scalarMult);
    function scalarMult_base(n) {
        check_ts_2.checkArrayTypes(n);
        if (n.length !== 32)
            throw new Error('bad n size');
        const q = array_ts_7.ByteArray(32);
        _scalarMult_base(q, n);
        return q;
    }
    exports_17("scalarMult_base", scalarMult_base);
    function _scalarMult(q, n, p) {
        const z = array_ts_7.ByteArray(32);
        const x = array_ts_7.NumArray(80);
        const a = core_ts_2.gf();
        const b = core_ts_2.gf();
        const c = core_ts_2.gf();
        const d = core_ts_2.gf();
        const e = core_ts_2.gf();
        const f = core_ts_2.gf();
        let r, i;
        for (i = 0; i < 31; i++)
            z[i] = n[i];
        z[31] = (n[31] & 127) | 64;
        z[0] &= 248;
        curve25519_ts_1.unpack25519(x, p);
        for (i = 0; i < 16; i++) {
            b[i] = x[i];
            d[i] = a[i] = c[i] = 0;
        }
        a[0] = d[0] = 1;
        for (i = 254; i >= 0; --i) {
            r = (z[i >>> 3] >>> (i & 7)) & 1;
            curve25519_ts_1.sel25519(a, b, r);
            curve25519_ts_1.sel25519(c, d, r);
            core_ts_2.A(e, a, c);
            core_ts_2.Z(a, a, c);
            core_ts_2.A(c, b, d);
            core_ts_2.Z(b, b, d);
            core_ts_2.S(d, e);
            core_ts_2.S(f, a);
            core_ts_2.M(a, c, a);
            core_ts_2.M(c, b, e);
            core_ts_2.A(e, a, c);
            core_ts_2.Z(a, a, c);
            core_ts_2.S(b, a);
            core_ts_2.Z(c, d, f);
            core_ts_2.M(a, c, core_ts_2._121665);
            core_ts_2.A(a, a, d);
            core_ts_2.M(c, c, a);
            core_ts_2.M(a, d, f);
            core_ts_2.M(d, b, x);
            core_ts_2.S(b, e);
            curve25519_ts_1.sel25519(a, b, r);
            curve25519_ts_1.sel25519(c, d, r);
        }
        for (i = 0; i < 16; i++) {
            x[i + 16] = a[i];
            x[i + 32] = c[i];
            x[i + 48] = b[i];
            x[i + 64] = d[i];
        }
        const x32 = x.subarray(32);
        const x16 = x.subarray(16);
        curve25519_ts_1.inv25519(x32, x32);
        core_ts_2.M(x16, x16, x32);
        curve25519_ts_1.pack25519(q, x16);
        return 0;
    }
    exports_17("_scalarMult", _scalarMult);
    function _scalarMult_base(q, n) {
        return _scalarMult(q, n, core_ts_2._9);
    }
    exports_17("_scalarMult_base", _scalarMult_base);
    return {
        setters: [
            function (array_ts_7_1) {
                array_ts_7 = array_ts_7_1;
            },
            function (core_ts_2_1) {
                core_ts_2 = core_ts_2_1;
            },
            function (curve25519_ts_1_1) {
                curve25519_ts_1 = curve25519_ts_1_1;
            },
            function (check_ts_2_1) {
                check_ts_2 = check_ts_2_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/box", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/core", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/random", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/salsa20", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/scalarmult", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/secretbox", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_18, context_18) {
    "use strict";
    var array_ts_8, core_ts_3, random_ts_1, salsa20_ts_2, scalarmult_ts_1, secretbox_ts_1, check_ts_3, box_after, box_open_after;
    var __moduleName = context_18 && context_18.id;
    function box(msg, nonce, publicKey, secretKey) {
        const k = box_before(publicKey, secretKey);
        return secretbox_ts_1.secretbox(msg, nonce, k);
    }
    exports_18("box", box);
    function box_before(publicKey, secretKey) {
        check_ts_3.checkArrayTypes(publicKey, secretKey);
        check_ts_3.checkBoxLengths(publicKey, secretKey);
        const k = array_ts_8.ByteArray(32);
        _box_beforenm(k, publicKey, secretKey);
        return k;
    }
    exports_18("box_before", box_before);
    function box_open(msg, nonce, publicKey, secretKey) {
        const k = box_before(publicKey, secretKey);
        return secretbox_ts_1.secretbox_open(msg, nonce, k);
    }
    exports_18("box_open", box_open);
    function box_keyPair() {
        const pk = array_ts_8.ByteArray(32);
        const sk = array_ts_8.ByteArray(32);
        _box_keypair(pk, sk);
        return { publicKey: pk, secretKey: sk };
    }
    exports_18("box_keyPair", box_keyPair);
    function box_keyPair_fromSecretKey(secretKey) {
        check_ts_3.checkArrayTypes(secretKey);
        if (secretKey.length !== 32)
            throw new Error(`bad secret key size (${secretKey.length}), should be ${32}`);
        const pk = array_ts_8.ByteArray(32);
        scalarmult_ts_1._scalarMult_base(pk, secretKey);
        return { publicKey: pk, secretKey: array_ts_8.ByteArray(secretKey) };
    }
    exports_18("box_keyPair_fromSecretKey", box_keyPair_fromSecretKey);
    function _box_keypair(y, x) {
        x.set(random_ts_1.randomBytes(32));
        return scalarmult_ts_1._scalarMult_base(y, x);
    }
    function _box_beforenm(k, y, x) {
        const s = array_ts_8.ByteArray(32);
        scalarmult_ts_1._scalarMult(s, x, y);
        return salsa20_ts_2._hsalsa20(k, core_ts_3._0, s, salsa20_ts_2._sigma);
    }
    return {
        setters: [
            function (array_ts_8_1) {
                array_ts_8 = array_ts_8_1;
            },
            function (core_ts_3_1) {
                core_ts_3 = core_ts_3_1;
            },
            function (random_ts_1_1) {
                random_ts_1 = random_ts_1_1;
            },
            function (salsa20_ts_2_1) {
                salsa20_ts_2 = salsa20_ts_2_1;
            },
            function (scalarmult_ts_1_1) {
                scalarmult_ts_1 = scalarmult_ts_1_1;
            },
            function (secretbox_ts_1_1) {
                secretbox_ts_1 = secretbox_ts_1_1;
            },
            function (check_ts_3_1) {
                check_ts_3 = check_ts_3_1;
            }
        ],
        execute: function () {
            exports_18("box_after", box_after = secretbox_ts_1.secretbox);
            exports_18("box_open_after", box_open_after = secretbox_ts_1.secretbox_open);
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check", [], function (exports_19, context_19) {
    "use strict";
    var __moduleName = context_19 && context_19.id;
    function checkLengths(k, n) {
        if (k.length != 32)
            throw new Error('bad key size');
        if (n.length != 24)
            throw new Error('bad nonce size');
    }
    exports_19("checkLengths", checkLengths);
    function checkBoxLengths(pk, sk) {
        if (pk.length != 32)
            throw new Error('bad public key size');
        if (sk.length != 32)
            throw new Error('bad secret key size');
    }
    exports_19("checkBoxLengths", checkBoxLengths);
    function checkArrayTypes(...arrays) {
        for (const array of arrays) {
            if (!(array instanceof Uint8Array)) {
                throw new TypeError('unexpected type, use ByteArray');
            }
        }
    }
    exports_19("checkArrayTypes", checkArrayTypes);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/verify", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_20, context_20) {
    "use strict";
    var check_ts_4;
    var __moduleName = context_20 && context_20.id;
    function vn(x, xi, y, yi, n) {
        let i, d = 0;
        for (i = 0; i < n; i++)
            d |= x[xi + i] ^ y[yi + i];
        return (1 & ((d - 1) >>> 8)) - 1;
    }
    function _verify_16(x, xi, y, yi) {
        return vn(x, xi, y, yi, 16);
    }
    exports_20("_verify_16", _verify_16);
    function _verify_32(x, xi, y, yi) {
        return vn(x, xi, y, yi, 32);
    }
    exports_20("_verify_32", _verify_32);
    function verify(x, y) {
        check_ts_4.checkArrayTypes(x, y);
        return x.length > 0 && y.length > 0 &&
            x.length == y.length &&
            vn(x, 0, y, 0, x.length) == 0;
    }
    exports_20("verify", verify);
    return {
        setters: [
            function (check_ts_4_1) {
                check_ts_4 = check_ts_4_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/hash", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_21, context_21) {
    "use strict";
    var array_ts_9, check_ts_5, _K;
    var __moduleName = context_21 && context_21.id;
    function hash(msg, len) {
        check_ts_5.checkArrayTypes(msg);
        const h = array_ts_9.ByteArray(len || 64);
        _hash(h, msg, msg.length);
        return h;
    }
    exports_21("hash", hash);
    function _hash(out, m, n) {
        const hh = array_ts_9.IntArray(8), hl = array_ts_9.IntArray(8), x = array_ts_9.ByteArray(256);
        let i, b = n;
        hh[0] = 0x6a09e667;
        hh[1] = 0xbb67ae85;
        hh[2] = 0x3c6ef372;
        hh[3] = 0xa54ff53a;
        hh[4] = 0x510e527f;
        hh[5] = 0x9b05688c;
        hh[6] = 0x1f83d9ab;
        hh[7] = 0x5be0cd19;
        hl[0] = 0xf3bcc908;
        hl[1] = 0x84caa73b;
        hl[2] = 0xfe94f82b;
        hl[3] = 0x5f1d36f1;
        hl[4] = 0xade682d1;
        hl[5] = 0x2b3e6c1f;
        hl[6] = 0xfb41bd6b;
        hl[7] = 0x137e2179;
        _hashblocks_hl(hh, hl, m, n);
        n %= 128;
        for (i = 0; i < n; i++)
            x[i] = m[b - n + i];
        x[n] = 128;
        n = 256 - 128 * (n < 112 ? 1 : 0);
        x[n - 9] = 0;
        _ts64(x, n - 8, (b / 0x20000000) | 0, b << 3);
        _hashblocks_hl(hh, hl, x, n);
        for (i = 0; i < 8; i++)
            _ts64(out, 8 * i, hh[i], hl[i]);
        return 0;
    }
    exports_21("_hash", _hash);
    function _hashblocks_hl(hh, hl, m, n) {
        const wh = array_ts_9.IntArray(16), wl = array_ts_9.IntArray(16);
        let bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7, bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7, th, tl, i, j, h, l, a, b, c, d;
        let ah0 = hh[0], ah1 = hh[1], ah2 = hh[2], ah3 = hh[3], ah4 = hh[4], ah5 = hh[5], ah6 = hh[6], ah7 = hh[7], al0 = hl[0], al1 = hl[1], al2 = hl[2], al3 = hl[3], al4 = hl[4], al5 = hl[5], al6 = hl[6], al7 = hl[7];
        let pos = 0;
        while (n >= 128) {
            for (i = 0; i < 16; i++) {
                j = 8 * i + pos;
                wh[i] = (m[j + 0] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
                wl[i] = (m[j + 4] << 24) | (m[j + 5] << 16) | (m[j + 6] << 8) | m[j + 7];
            }
            for (i = 0; i < 80; i++) {
                bh0 = ah0;
                bh1 = ah1;
                bh2 = ah2;
                bh3 = ah3;
                bh4 = ah4;
                bh5 = ah5;
                bh6 = ah6;
                bh7 = ah7;
                bl0 = al0;
                bl1 = al1;
                bl2 = al2;
                bl3 = al3;
                bl4 = al4;
                bl5 = al5;
                bl6 = al6;
                bl7 = al7;
                h = ah7;
                l = al7;
                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;
                h = ((ah4 >>> 14) | (al4 << (32 - 14))) ^ ((ah4 >>> 18) | (al4 << (32 - 18))) ^ ((al4 >>> (41 - 32)) | (ah4 << (32 - (41 - 32))));
                l = ((al4 >>> 14) | (ah4 << (32 - 14))) ^ ((al4 >>> 18) | (ah4 << (32 - 18))) ^ ((ah4 >>> (41 - 32)) | (al4 << (32 - (41 - 32))));
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                h = (ah4 & ah5) ^ (~ah4 & ah6);
                l = (al4 & al5) ^ (~al4 & al6);
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                h = _K[i * 2];
                l = _K[i * 2 + 1];
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                h = wh[i % 16];
                l = wl[i % 16];
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;
                th = c & 0xffff | d << 16;
                tl = a & 0xffff | b << 16;
                h = th;
                l = tl;
                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;
                h = ((ah0 >>> 28) | (al0 << (32 - 28))) ^ ((al0 >>> (34 - 32)) | (ah0 << (32 - (34 - 32)))) ^ ((al0 >>> (39 - 32)) | (ah0 << (32 - (39 - 32))));
                l = ((al0 >>> 28) | (ah0 << (32 - 28))) ^ ((ah0 >>> (34 - 32)) | (al0 << (32 - (34 - 32)))) ^ ((ah0 >>> (39 - 32)) | (al0 << (32 - (39 - 32))));
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
                l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;
                bh7 = (c & 0xffff) | (d << 16);
                bl7 = (a & 0xffff) | (b << 16);
                h = bh3;
                l = bl3;
                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;
                h = th;
                l = tl;
                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;
                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;
                bh3 = (c & 0xffff) | (d << 16);
                bl3 = (a & 0xffff) | (b << 16);
                ah1 = bh0;
                ah2 = bh1;
                ah3 = bh2;
                ah4 = bh3;
                ah5 = bh4;
                ah6 = bh5;
                ah7 = bh6;
                ah0 = bh7;
                al1 = bl0;
                al2 = bl1;
                al3 = bl2;
                al4 = bl3;
                al5 = bl4;
                al6 = bl5;
                al7 = bl6;
                al0 = bl7;
                if (i % 16 === 15) {
                    for (j = 0; j < 16; j++) {
                        h = wh[j];
                        l = wl[j];
                        a = l & 0xffff;
                        b = l >>> 16;
                        c = h & 0xffff;
                        d = h >>> 16;
                        h = wh[(j + 9) % 16];
                        l = wl[(j + 9) % 16];
                        a += l & 0xffff;
                        b += l >>> 16;
                        c += h & 0xffff;
                        d += h >>> 16;
                        th = wh[(j + 1) % 16];
                        tl = wl[(j + 1) % 16];
                        h = ((th >>> 1) | (tl << (32 - 1))) ^ ((th >>> 8) | (tl << (32 - 8))) ^ (th >>> 7);
                        l = ((tl >>> 1) | (th << (32 - 1))) ^ ((tl >>> 8) | (th << (32 - 8))) ^ ((tl >>> 7) | (th << (32 - 7)));
                        a += l & 0xffff;
                        b += l >>> 16;
                        c += h & 0xffff;
                        d += h >>> 16;
                        th = wh[(j + 14) % 16];
                        tl = wl[(j + 14) % 16];
                        h = ((th >>> 19) | (tl << (32 - 19))) ^ ((tl >>> (61 - 32)) | (th << (32 - (61 - 32)))) ^ (th >>> 6);
                        l = ((tl >>> 19) | (th << (32 - 19))) ^ ((th >>> (61 - 32)) | (tl << (32 - (61 - 32)))) ^ ((tl >>> 6) | (th << (32 - 6)));
                        a += l & 0xffff;
                        b += l >>> 16;
                        c += h & 0xffff;
                        d += h >>> 16;
                        b += a >>> 16;
                        c += b >>> 16;
                        d += c >>> 16;
                        wh[j] = (c & 0xffff) | (d << 16);
                        wl[j] = (a & 0xffff) | (b << 16);
                    }
                }
            }
            h = ah0;
            l = al0;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[0];
            l = hl[0];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[0] = ah0 = (c & 0xffff) | (d << 16);
            hl[0] = al0 = (a & 0xffff) | (b << 16);
            h = ah1;
            l = al1;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[1];
            l = hl[1];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[1] = ah1 = (c & 0xffff) | (d << 16);
            hl[1] = al1 = (a & 0xffff) | (b << 16);
            h = ah2;
            l = al2;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[2];
            l = hl[2];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[2] = ah2 = (c & 0xffff) | (d << 16);
            hl[2] = al2 = (a & 0xffff) | (b << 16);
            h = ah3;
            l = al3;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[3];
            l = hl[3];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[3] = ah3 = (c & 0xffff) | (d << 16);
            hl[3] = al3 = (a & 0xffff) | (b << 16);
            h = ah4;
            l = al4;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[4];
            l = hl[4];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[4] = ah4 = (c & 0xffff) | (d << 16);
            hl[4] = al4 = (a & 0xffff) | (b << 16);
            h = ah5;
            l = al5;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[5];
            l = hl[5];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[5] = ah5 = (c & 0xffff) | (d << 16);
            hl[5] = al5 = (a & 0xffff) | (b << 16);
            h = ah6;
            l = al6;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[6];
            l = hl[6];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[6] = ah6 = (c & 0xffff) | (d << 16);
            hl[6] = al6 = (a & 0xffff) | (b << 16);
            h = ah7;
            l = al7;
            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;
            h = hh[7];
            l = hl[7];
            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            hh[7] = ah7 = (c & 0xffff) | (d << 16);
            hl[7] = al7 = (a & 0xffff) | (b << 16);
            pos += 128;
            n -= 128;
        }
        return n;
    }
    function _ts64(x, i, h, l) {
        x[i] = (h >> 24) & 0xff;
        x[i + 1] = (h >> 16) & 0xff;
        x[i + 2] = (h >> 8) & 0xff;
        x[i + 3] = h & 0xff;
        x[i + 4] = (l >> 24) & 0xff;
        x[i + 5] = (l >> 16) & 0xff;
        x[i + 6] = (l >> 8) & 0xff;
        x[i + 7] = l & 0xff;
    }
    return {
        setters: [
            function (array_ts_9_1) {
                array_ts_9 = array_ts_9_1;
            },
            function (check_ts_5_1) {
                check_ts_5 = check_ts_5_1;
            }
        ],
        execute: function () {
            _K = [
                0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
                0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
                0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
                0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
                0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
                0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
                0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
                0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
                0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
                0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
                0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
                0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
                0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
                0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
                0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
                0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
                0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
                0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
                0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
                0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
                0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
                0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
                0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
                0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
                0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
                0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
                0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
                0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
                0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
                0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
                0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
                0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
                0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
                0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
                0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
                0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
                0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
                0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
                0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
                0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
            ];
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/sign", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/verify", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/core", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/random", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/curve25519", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/hash", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/check"], function (exports_22, context_22) {
    "use strict";
    var array_ts_10, verify_ts_3, core_ts_4, random_ts_2, curve25519_ts_2, hash_ts_1, check_ts_6, L;
    var __moduleName = context_22 && context_22.id;
    function sign(msg, secretKey) {
        check_ts_6.checkArrayTypes(msg, secretKey);
        if (secretKey.length !== 64)
            throw new Error('bad secret key size');
        const signedMsg = array_ts_10.ByteArray(64 + msg.length);
        _sign(signedMsg, msg, msg.length, secretKey);
        return signedMsg;
    }
    exports_22("sign", sign);
    function sign_open(signedMsg, publicKey) {
        check_ts_6.checkArrayTypes(signedMsg, publicKey);
        if (publicKey.length !== 32)
            throw new Error('bad public key size');
        const tmp = array_ts_10.ByteArray(signedMsg.length);
        const mlen = _sign_open(tmp, signedMsg, signedMsg.length, publicKey);
        if (mlen < 0)
            return;
        const m = array_ts_10.ByteArray(mlen);
        for (let i = 0; i < m.length; i++)
            m[i] = tmp[i];
        return m;
    }
    exports_22("sign_open", sign_open);
    function sign_detached(msg, secretKey) {
        const signedMsg = sign(msg, secretKey);
        const sig = array_ts_10.ByteArray(64);
        for (let i = 0; i < sig.length; i++)
            sig[i] = signedMsg[i];
        return sig;
    }
    exports_22("sign_detached", sign_detached);
    function sign_detached_verify(msg, sig, publicKey) {
        check_ts_6.checkArrayTypes(msg, sig, publicKey);
        if (sig.length !== 64)
            throw new Error('bad signature size');
        if (publicKey.length !== 32)
            throw new Error('bad public key size');
        const sm = array_ts_10.ByteArray(64 + msg.length);
        const m = array_ts_10.ByteArray(64 + msg.length);
        let i;
        for (i = 0; i < 64; i++)
            sm[i] = sig[i];
        for (i = 0; i < msg.length; i++)
            sm[i + 64] = msg[i];
        return _sign_open(m, sm, sm.length, publicKey) >= 0;
    }
    exports_22("sign_detached_verify", sign_detached_verify);
    function sign_keyPair() {
        const pk = array_ts_10.ByteArray(32);
        const sk = array_ts_10.ByteArray(64);
        _sign_keypair(pk, sk, false);
        return { publicKey: pk, secretKey: sk };
    }
    exports_22("sign_keyPair", sign_keyPair);
    function sign_keyPair_fromSecretKey(secretKey) {
        check_ts_6.checkArrayTypes(secretKey);
        if (secretKey.length !== 64)
            throw new Error('bad secret key size');
        const pk = array_ts_10.ByteArray(32);
        for (let i = 0; i < pk.length; i++)
            pk[i] = secretKey[32 + i];
        return { publicKey: pk, secretKey: array_ts_10.ByteArray(secretKey) };
    }
    exports_22("sign_keyPair_fromSecretKey", sign_keyPair_fromSecretKey);
    function sign_keyPair_fromSeed(seed) {
        check_ts_6.checkArrayTypes(seed);
        if (seed.length !== 32)
            throw new Error('bad seed size');
        const pk = array_ts_10.ByteArray(32);
        const sk = array_ts_10.ByteArray(64);
        for (let i = 0; i < 32; i++)
            sk[i] = seed[i];
        _sign_keypair(pk, sk, true);
        return { publicKey: pk, secretKey: sk };
    }
    exports_22("sign_keyPair_fromSeed", sign_keyPair_fromSeed);
    function _sign_keypair(pk, sk, seeded) {
        const d = array_ts_10.ByteArray(64);
        const p = [core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf()];
        let i;
        if (!seeded)
            sk.set(random_ts_2.randomBytes(32));
        hash_ts_1._hash(d, sk, 32);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
        scalarbase(p, d);
        pack(pk, p);
        for (i = 0; i < 32; i++)
            sk[i + 32] = pk[i];
        return 0;
    }
    function _sign(sm, m, n, sk) {
        const d = array_ts_10.ByteArray(64), h = array_ts_10.ByteArray(64), r = array_ts_10.ByteArray(64);
        const x = array_ts_10.NumArray(64);
        const p = [core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf()];
        let i, j;
        hash_ts_1._hash(d, sk, 32);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
        const smlen = n + 64;
        for (i = 0; i < n; i++)
            sm[64 + i] = m[i];
        for (i = 0; i < 32; i++)
            sm[32 + i] = d[32 + i];
        hash_ts_1._hash(r, sm.subarray(32), n + 32);
        reduce(r);
        scalarbase(p, r);
        pack(sm, p);
        for (i = 32; i < 64; i++)
            sm[i] = sk[i];
        hash_ts_1._hash(h, sm, n + 64);
        reduce(h);
        for (i = 0; i < 64; i++)
            x[i] = 0;
        for (i = 0; i < 32; i++)
            x[i] = r[i];
        for (i = 0; i < 32; i++) {
            for (j = 0; j < 32; j++) {
                x[i + j] += h[i] * d[j];
            }
        }
        modL(sm.subarray(32), x);
        return smlen;
    }
    function _sign_open(m, sm, n, pk) {
        const t = array_ts_10.ByteArray(32), h = array_ts_10.ByteArray(64);
        const p = [core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf()], q = [core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf()];
        let i, mlen;
        mlen = -1;
        if (n < 64 || unpackneg(q, pk))
            return -1;
        for (i = 0; i < n; i++)
            m[i] = sm[i];
        for (i = 0; i < 32; i++)
            m[i + 32] = pk[i];
        hash_ts_1._hash(h, m, n);
        reduce(h);
        scalarmult(p, q, h);
        scalarbase(q, sm.subarray(32));
        add(p, q);
        pack(t, p);
        n -= 64;
        if (verify_ts_3._verify_32(sm, 0, t, 0)) {
            for (i = 0; i < n; i++)
                m[i] = 0;
            return -1;
        }
        for (i = 0; i < n; i++)
            m[i] = sm[i + 64];
        mlen = n;
        return mlen;
    }
    function scalarbase(p, s) {
        const q = [core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf(), core_ts_4.gf()];
        curve25519_ts_2.set25519(q[0], core_ts_4.X);
        curve25519_ts_2.set25519(q[1], core_ts_4.Y);
        curve25519_ts_2.set25519(q[2], core_ts_4.gf1);
        core_ts_4.M(q[3], core_ts_4.X, core_ts_4.Y);
        scalarmult(p, q, s);
    }
    exports_22("scalarbase", scalarbase);
    function scalarmult(p, q, s) {
        let b, i;
        curve25519_ts_2.set25519(p[0], core_ts_4.gf0);
        curve25519_ts_2.set25519(p[1], core_ts_4.gf1);
        curve25519_ts_2.set25519(p[2], core_ts_4.gf1);
        curve25519_ts_2.set25519(p[3], core_ts_4.gf0);
        for (i = 255; i >= 0; --i) {
            b = (s[(i / 8) | 0] >> (i & 7)) & 1;
            cswap(p, q, b);
            add(q, p);
            add(p, p);
            cswap(p, q, b);
        }
    }
    exports_22("scalarmult", scalarmult);
    function pack(r, p) {
        const tx = core_ts_4.gf(), ty = core_ts_4.gf(), zi = core_ts_4.gf();
        curve25519_ts_2.inv25519(zi, p[2]);
        core_ts_4.M(tx, p[0], zi);
        core_ts_4.M(ty, p[1], zi);
        curve25519_ts_2.pack25519(r, ty);
        r[31] ^= curve25519_ts_2.par25519(tx) << 7;
    }
    function unpackneg(r, p) {
        const t = core_ts_4.gf(), chk = core_ts_4.gf(), num = core_ts_4.gf(), den = core_ts_4.gf(), den2 = core_ts_4.gf(), den4 = core_ts_4.gf(), den6 = core_ts_4.gf();
        curve25519_ts_2.set25519(r[2], core_ts_4.gf1);
        curve25519_ts_2.unpack25519(r[1], p);
        core_ts_4.S(num, r[1]);
        core_ts_4.M(den, num, core_ts_4.D);
        core_ts_4.Z(num, num, r[2]);
        core_ts_4.A(den, r[2], den);
        core_ts_4.S(den2, den);
        core_ts_4.S(den4, den2);
        core_ts_4.M(den6, den4, den2);
        core_ts_4.M(t, den6, num);
        core_ts_4.M(t, t, den);
        pow2523(t, t);
        core_ts_4.M(t, t, num);
        core_ts_4.M(t, t, den);
        core_ts_4.M(t, t, den);
        core_ts_4.M(r[0], t, den);
        core_ts_4.S(chk, r[0]);
        core_ts_4.M(chk, chk, den);
        if (curve25519_ts_2.neq25519(chk, num))
            core_ts_4.M(r[0], r[0], core_ts_4.I);
        core_ts_4.S(chk, r[0]);
        core_ts_4.M(chk, chk, den);
        if (curve25519_ts_2.neq25519(chk, num))
            return -1;
        if (curve25519_ts_2.par25519(r[0]) === (p[31] >> 7))
            core_ts_4.Z(r[0], core_ts_4.gf0, r[0]);
        core_ts_4.M(r[3], r[0], r[1]);
        return 0;
    }
    function reduce(r) {
        const x = array_ts_10.NumArray(64);
        let i;
        for (i = 0; i < 64; i++)
            x[i] = r[i];
        for (i = 0; i < 64; i++)
            r[i] = 0;
        modL(r, x);
    }
    function modL(r, x) {
        let carry, i, j, k;
        for (i = 63; i >= 32; --i) {
            carry = 0;
            for (j = i - 32, k = i - 12; j < k; ++j) {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry * 256;
            }
            x[j] += carry;
            x[i] = 0;
        }
        carry = 0;
        for (j = 0; j < 32; j++) {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for (j = 0; j < 32; j++)
            x[j] -= carry * L[j];
        for (i = 0; i < 32; i++) {
            x[i + 1] += x[i] >> 8;
            r[i] = x[i] & 255;
        }
    }
    function add(p, q) {
        const a = core_ts_4.gf(), b = core_ts_4.gf(), c = core_ts_4.gf(), d = core_ts_4.gf(), e = core_ts_4.gf(), f = core_ts_4.gf(), g = core_ts_4.gf(), h = core_ts_4.gf(), t = core_ts_4.gf();
        core_ts_4.Z(a, p[1], p[0]);
        core_ts_4.Z(t, q[1], q[0]);
        core_ts_4.M(a, a, t);
        core_ts_4.A(b, p[0], p[1]);
        core_ts_4.A(t, q[0], q[1]);
        core_ts_4.M(b, b, t);
        core_ts_4.M(c, p[3], q[3]);
        core_ts_4.M(c, c, core_ts_4.D2);
        core_ts_4.M(d, p[2], q[2]);
        core_ts_4.A(d, d, d);
        core_ts_4.Z(e, b, a);
        core_ts_4.Z(f, d, c);
        core_ts_4.A(g, d, c);
        core_ts_4.A(h, b, a);
        core_ts_4.M(p[0], e, f);
        core_ts_4.M(p[1], h, g);
        core_ts_4.M(p[2], g, f);
        core_ts_4.M(p[3], e, h);
    }
    function cswap(p, q, b) {
        for (let i = 0; i < 4; i++) {
            curve25519_ts_2.sel25519(p[i], q[i], b);
        }
    }
    function pow2523(o, i) {
        const c = core_ts_4.gf();
        let a;
        for (a = 0; a < 16; a++)
            c[a] = i[a];
        for (a = 250; a >= 0; a--) {
            core_ts_4.S(c, c);
            if (a !== 1)
                core_ts_4.M(c, c, i);
        }
        for (a = 0; a < 16; a++)
            o[a] = c[a];
    }
    return {
        setters: [
            function (array_ts_10_1) {
                array_ts_10 = array_ts_10_1;
            },
            function (verify_ts_3_1) {
                verify_ts_3 = verify_ts_3_1;
            },
            function (core_ts_4_1) {
                core_ts_4 = core_ts_4_1;
            },
            function (random_ts_2_1) {
                random_ts_2 = random_ts_2_1;
            },
            function (curve25519_ts_2_1) {
                curve25519_ts_2 = curve25519_ts_2_1;
            },
            function (hash_ts_1_1) {
                hash_ts_1 = hash_ts_1_1;
            },
            function (check_ts_6_1) {
                check_ts_6 = check_ts_6_1;
            }
        ],
        execute: function () {
            L = array_ts_10.NumArray([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/auth", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/hash"], function (exports_23, context_23) {
    "use strict";
    var array_ts_11, hash_ts_2, BLOCK_SIZE, HASH_SIZE, auth_full;
    var __moduleName = context_23 && context_23.id;
    function auth(msg, key) {
        const out = array_ts_11.ByteArray(32);
        out.set(hmac(msg, key).subarray(0, 32));
        return out;
    }
    exports_23("auth", auth);
    function hmac(msg, key) {
        const buf = array_ts_11.ByteArray(BLOCK_SIZE + Math.max(HASH_SIZE, msg.length));
        let i, innerHash;
        if (key.length > BLOCK_SIZE)
            key = hash_ts_2.hash(key);
        for (i = 0; i < BLOCK_SIZE; i++)
            buf[i] = 0x36;
        for (i = 0; i < key.length; i++)
            buf[i] ^= key[i];
        buf.set(msg, BLOCK_SIZE);
        innerHash = hash_ts_2.hash(buf.subarray(0, BLOCK_SIZE + msg.length));
        for (i = 0; i < BLOCK_SIZE; i++)
            buf[i] = 0x5c;
        for (i = 0; i < key.length; i++)
            buf[i] ^= key[i];
        buf.set(innerHash, BLOCK_SIZE);
        return hash_ts_2.hash(buf.subarray(0, BLOCK_SIZE + innerHash.length));
    }
    return {
        setters: [
            function (array_ts_11_1) {
                array_ts_11 = array_ts_11_1;
            },
            function (hash_ts_2_1) {
                hash_ts_2 = hash_ts_2_1;
            }
        ],
        execute: function () {
            BLOCK_SIZE = 128;
            HASH_SIZE = 64;
            exports_23("auth_full", auth_full = hmac);
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/blake2s", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_24, context_24) {
    "use strict";
    var array_ts_12, BLAKE2S_IV, SIGMA, v, m;
    var __moduleName = context_24 && context_24.id;
    function blake2s(input, key, outlen = 32) {
        const ctx = blake2s_init(outlen, key);
        blake2s_update(ctx, input);
        return blake2s_final(ctx);
    }
    exports_24("blake2s", blake2s);
    function blake2s_init(outlen, key) {
        if (!(outlen > 0 && outlen <= 32)) {
            throw new Error('Incorrect output length, should be in [1, 32]');
        }
        const keylen = key ? key.length : 0;
        if (key && !(keylen > 0 && keylen <= 32)) {
            throw new Error('Incorrect key length, should be in [1, 32]');
        }
        const ctx = {
            h: array_ts_12.WordArray(BLAKE2S_IV),
            b: array_ts_12.WordArray(64),
            c: 0,
            t: 0,
            outlen: outlen
        };
        ctx.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
        if (keylen) {
            blake2s_update(ctx, key);
            ctx.c = 64;
        }
        return ctx;
    }
    exports_24("blake2s_init", blake2s_init);
    function blake2s_update(ctx, input) {
        for (let i = 0; i < input.length; i++) {
            if (ctx.c === 64) {
                ctx.t += ctx.c;
                blake2s_compress(ctx, false);
                ctx.c = 0;
            }
            ctx.b[ctx.c++] = input[i];
        }
    }
    exports_24("blake2s_update", blake2s_update);
    function blake2s_final(ctx) {
        ctx.t += ctx.c;
        while (ctx.c < 64) {
            ctx.b[ctx.c++] = 0;
        }
        blake2s_compress(ctx, true);
        const out = array_ts_12.ByteArray(ctx.outlen);
        for (var i = 0; i < ctx.outlen; i++) {
            out[i] = (ctx.h[i >> 2] >> (8 * (i & 3))) & 0xFF;
        }
        return out;
    }
    exports_24("blake2s_final", blake2s_final);
    function blake2s_compress(ctx, last) {
        let i = 0;
        for (i = 0; i < 8; i++) {
            v[i] = ctx.h[i];
            v[i + 8] = BLAKE2S_IV[i];
        }
        v[12] ^= ctx.t;
        v[13] ^= (ctx.t / 0x100000000);
        if (last) {
            v[14] = ~v[14];
        }
        for (i = 0; i < 16; i++) {
            m[i] = B2S_GET32(ctx.b, 4 * i);
        }
        for (i = 0; i < 10; i++) {
            B2S_G(0, 4, 8, 12, m[SIGMA[i * 16 + 0]], m[SIGMA[i * 16 + 1]]);
            B2S_G(1, 5, 9, 13, m[SIGMA[i * 16 + 2]], m[SIGMA[i * 16 + 3]]);
            B2S_G(2, 6, 10, 14, m[SIGMA[i * 16 + 4]], m[SIGMA[i * 16 + 5]]);
            B2S_G(3, 7, 11, 15, m[SIGMA[i * 16 + 6]], m[SIGMA[i * 16 + 7]]);
            B2S_G(0, 5, 10, 15, m[SIGMA[i * 16 + 8]], m[SIGMA[i * 16 + 9]]);
            B2S_G(1, 6, 11, 12, m[SIGMA[i * 16 + 10]], m[SIGMA[i * 16 + 11]]);
            B2S_G(2, 7, 8, 13, m[SIGMA[i * 16 + 12]], m[SIGMA[i * 16 + 13]]);
            B2S_G(3, 4, 9, 14, m[SIGMA[i * 16 + 14]], m[SIGMA[i * 16 + 15]]);
        }
        for (i = 0; i < 8; i++) {
            ctx.h[i] ^= v[i] ^ v[i + 8];
        }
    }
    function B2S_GET32(v, i) {
        return v[i] ^ (v[i + 1] << 8) ^ (v[i + 2] << 16) ^ (v[i + 3] << 24);
    }
    function B2S_G(a, b, c, d, x, y) {
        v[a] = v[a] + v[b] + x;
        v[d] = ROTR32(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = ROTR32(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = ROTR32(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = ROTR32(v[b] ^ v[c], 7);
    }
    function ROTR32(x, y) {
        return (x >>> y) ^ (x << (32 - y));
    }
    return {
        setters: [
            function (array_ts_12_1) {
                array_ts_12 = array_ts_12_1;
            }
        ],
        execute: function () {
            BLAKE2S_IV = array_ts_12.WordArray([
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
            ]);
            SIGMA = array_ts_12.ByteArray([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
                12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
                13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
                6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
                10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
            ]);
            v = array_ts_12.WordArray(16);
            m = array_ts_12.WordArray(16);
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/blake2b", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array"], function (exports_25, context_25) {
    "use strict";
    var array_ts_13, BLAKE2B_IV32, SIGMA8, SIGMA82, v, m;
    var __moduleName = context_25 && context_25.id;
    function blake2b(input, key, outlen = 64) {
        const ctx = blake2b_init(outlen, key);
        blake2b_update(ctx, input);
        return blake2b_final(ctx);
    }
    exports_25("blake2b", blake2b);
    function blake2b_init(outlen, key) {
        if (outlen === 0 || outlen > 64)
            throw new Error('Illegal output length, expected 0 < length <= 64');
        if (key && key.length > 64)
            throw new Error('Illegal key, expected Uint8Array with 0 < length <= 64');
        const h = array_ts_13.WordArray(16);
        for (let i = 0; i < 16; i++)
            h[i] = BLAKE2B_IV32[i];
        const keylen = key ? key.length : 0;
        h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
        const ctx = {
            b: array_ts_13.ByteArray(128),
            h,
            t: 0,
            c: 0,
            outlen
        };
        if (key) {
            blake2b_update(ctx, key);
            ctx.c = 128;
        }
        return ctx;
    }
    exports_25("blake2b_init", blake2b_init);
    function blake2b_update(ctx, input) {
        for (let i = 0; i < input.length; i++) {
            if (ctx.c === 128) {
                ctx.t += ctx.c;
                blake2b_compress(ctx, false);
                ctx.c = 0;
            }
            ctx.b[ctx.c++] = input[i];
        }
    }
    exports_25("blake2b_update", blake2b_update);
    function blake2b_final(ctx) {
        ctx.t += ctx.c;
        while (ctx.c < 128) {
            ctx.b[ctx.c++] = 0;
        }
        blake2b_compress(ctx, true);
        const out = array_ts_13.ByteArray(ctx.outlen);
        for (let i = 0; i < ctx.outlen; i++) {
            out[i] = ctx.h[i >> 2] >> (8 * (i & 3));
        }
        return out;
    }
    exports_25("blake2b_final", blake2b_final);
    function blake2b_compress(ctx, last) {
        let i;
        for (i = 0; i < 16; i++) {
            v[i] = ctx.h[i];
            v[i + 16] = BLAKE2B_IV32[i];
        }
        v[24] = v[24] ^ ctx.t;
        v[25] = v[25] ^ (ctx.t / 0x100000000);
        if (last) {
            v[28] = ~v[28];
            v[29] = ~v[29];
        }
        for (i = 0; i < 32; i++) {
            m[i] = B2B_GET32(ctx.h, 4 * i);
        }
        for (i = 0; i < 12; i++) {
            B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1]);
            B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3]);
            B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5]);
            B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7]);
            B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9]);
            B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11]);
            B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13]);
            B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15]);
        }
        for (i = 0; i < 16; i++) {
            ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 16];
        }
    }
    function ADD64AA(v, a, b) {
        let o0 = v[a] + v[b], o1 = v[a + 1] + v[b + 1];
        if (o0 >= 0x100000000)
            o1++;
        v[a] = o0;
        v[a + 1] = o1;
    }
    function ADD64AC(v, a, b0, b1) {
        let o0 = v[a] + b0;
        if (b0 < 0)
            o0 += 0x100000000;
        let o1 = v[a + 1] + b1;
        if (o0 >= 0x100000000)
            o1++;
        v[a] = o0;
        v[a + 1] = o1;
    }
    function B2B_GET32(arr, i) {
        return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
    }
    function B2B_G(a, b, c, d, ix, iy) {
        const x0 = m[ix];
        const x1 = m[ix + 1];
        const y0 = m[iy];
        const y1 = m[iy + 1];
        ADD64AA(v, a, b);
        ADD64AC(v, a, x0, x1);
        let xor0 = v[d] ^ v[a];
        let xor1 = v[d + 1] ^ v[a + 1];
        v[d] = xor1;
        v[d + 1] = xor0;
        ADD64AA(v, c, d);
        xor0 = v[b] ^ v[c];
        xor1 = v[b + 1] ^ v[c + 1];
        v[b] = (xor0 >>> 24) ^ (xor1 << 8);
        v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
        ADD64AA(v, a, b);
        ADD64AC(v, a, y0, y1);
        xor0 = v[d] ^ v[a];
        xor1 = v[d + 1] ^ v[a + 1];
        v[d] = (xor0 >>> 16) ^ (xor1 << 16);
        v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
        ADD64AA(v, c, d);
        xor0 = v[b] ^ v[c];
        xor1 = v[b + 1] ^ v[c + 1];
        v[b] = (xor1 >>> 31) ^ (xor0 << 1);
        v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
    }
    return {
        setters: [
            function (array_ts_13_1) {
                array_ts_13 = array_ts_13_1;
            }
        ],
        execute: function () {
            BLAKE2B_IV32 = array_ts_13.WordArray([
                0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85,
                0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A,
                0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C,
                0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19
            ]);
            SIGMA8 = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
                11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
                7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
                9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
                2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
                12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
                13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
                6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
                10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
            ];
            SIGMA82 = array_ts_13.ByteArray(SIGMA8.map(x => x * 2));
            v = array_ts_13.WordArray(32);
            m = array_ts_13.WordArray(32);
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/sealedbox", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/box", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/blake2b"], function (exports_26, context_26) {
    "use strict";
    var array_ts_14, box_ts_1, blake2b_ts_1;
    var __moduleName = context_26 && context_26.id;
    function sealedbox(m, pk) {
        const c = array_ts_14.ByteArray(48 + m.length);
        const ek = box_ts_1.box_keyPair();
        c.set(ek.publicKey);
        const nonce = nonce_gen(ek.publicKey, pk);
        const boxed = box_ts_1.box(m, nonce, pk, ek.secretKey);
        c.set(boxed, ek.publicKey.length);
        for (let i = 0; i < ek.secretKey.length; i++)
            ek.secretKey[i] = 0;
        return c;
    }
    exports_26("sealedbox", sealedbox);
    function sealedbox_open(c, pk, sk) {
        if (c.length < 48)
            return;
        const epk = c.subarray(0, 32);
        const nonce = nonce_gen(epk, pk);
        const boxData = c.subarray(32);
        return box_ts_1.box_open(boxData, nonce, epk, sk);
    }
    exports_26("sealedbox_open", sealedbox_open);
    function nonce_gen(pk1, pk2) {
        const state = blake2b_ts_1.blake2b_init(24);
        blake2b_ts_1.blake2b_update(state, pk1);
        blake2b_ts_1.blake2b_update(state, pk2);
        return blake2b_ts_1.blake2b_final(state);
    }
    return {
        setters: [
            function (array_ts_14_1) {
                array_ts_14 = array_ts_14_1;
            },
            function (box_ts_1_1) {
                box_ts_1 = box_ts_1_1;
            },
            function (blake2b_ts_1_1) {
                blake2b_ts_1 = blake2b_ts_1_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/nacl", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/array", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/validate", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/convert", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/verify", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/random", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/scalarmult", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/secretbox", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/box", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/sign", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/hash", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/auth", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/blake2s", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/blake2b", "https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/sealedbox"], function (exports_27, context_27) {
    "use strict";
    var __moduleName = context_27 && context_27.id;
    function exportStar_2(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default") exports[n] = m[n];
        }
        exports_27(exports);
    }
    return {
        setters: [
            function (array_ts_15_1) {
                exportStar_2(array_ts_15_1);
            },
            function (validate_ts_2_1) {
                exportStar_2(validate_ts_2_1);
            },
            function (convert_ts_2_1) {
                exportStar_2(convert_ts_2_1);
            },
            function (verify_ts_4_1) {
                exportStar_2(verify_ts_4_1);
            },
            function (random_ts_3_1) {
                exportStar_2(random_ts_3_1);
            },
            function (scalarmult_ts_2_1) {
                exportStar_2(scalarmult_ts_2_1);
            },
            function (secretbox_ts_2_1) {
                exportStar_2(secretbox_ts_2_1);
            },
            function (box_ts_2_1) {
                exportStar_2(box_ts_2_1);
            },
            function (sign_ts_1_1) {
                exportStar_2(sign_ts_1_1);
            },
            function (hash_ts_3_1) {
                exportStar_2(hash_ts_3_1);
            },
            function (auth_ts_1_1) {
                exportStar_2(auth_ts_1_1);
            },
            function (blake2s_ts_1_1) {
                exportStar_2(blake2s_ts_1_1);
            },
            function (blake2b_ts_2_1) {
                exportStar_2(blake2b_ts_2_1);
            },
            function (sealedbox_ts_1_1) {
                exportStar_2(sealedbox_ts_1_1);
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/modules/esm/deps", ["https://raw.githubusercontent.com/aricart/tweetnacl-deno/import-type-fixes/src/nacl"], function (exports_28, context_28) {
    "use strict";
    var nacl_ts_1, denoHelper;
    var __moduleName = context_28 && context_28.id;
    return {
        setters: [
            function (nacl_ts_1_1) {
                nacl_ts_1 = nacl_ts_1_1;
            }
        ],
        execute: function () {
            exports_28("denoHelper", denoHelper = {
                fromSeed: nacl_ts_1.sign_keyPair_fromSeed,
                sign: nacl_ts_1.sign_detached,
                verify: nacl_ts_1.sign_detached_verify,
                randomBytes: nacl_ts_1.randomBytes,
            });
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/crc16", [], function (exports_29, context_29) {
    "use strict";
    var crc16tab, crc16;
    var __moduleName = context_29 && context_29.id;
    return {
        setters: [],
        execute: function () {
            crc16tab = new Uint16Array([
                0x0000,
                0x1021,
                0x2042,
                0x3063,
                0x4084,
                0x50a5,
                0x60c6,
                0x70e7,
                0x8108,
                0x9129,
                0xa14a,
                0xb16b,
                0xc18c,
                0xd1ad,
                0xe1ce,
                0xf1ef,
                0x1231,
                0x0210,
                0x3273,
                0x2252,
                0x52b5,
                0x4294,
                0x72f7,
                0x62d6,
                0x9339,
                0x8318,
                0xb37b,
                0xa35a,
                0xd3bd,
                0xc39c,
                0xf3ff,
                0xe3de,
                0x2462,
                0x3443,
                0x0420,
                0x1401,
                0x64e6,
                0x74c7,
                0x44a4,
                0x5485,
                0xa56a,
                0xb54b,
                0x8528,
                0x9509,
                0xe5ee,
                0xf5cf,
                0xc5ac,
                0xd58d,
                0x3653,
                0x2672,
                0x1611,
                0x0630,
                0x76d7,
                0x66f6,
                0x5695,
                0x46b4,
                0xb75b,
                0xa77a,
                0x9719,
                0x8738,
                0xf7df,
                0xe7fe,
                0xd79d,
                0xc7bc,
                0x48c4,
                0x58e5,
                0x6886,
                0x78a7,
                0x0840,
                0x1861,
                0x2802,
                0x3823,
                0xc9cc,
                0xd9ed,
                0xe98e,
                0xf9af,
                0x8948,
                0x9969,
                0xa90a,
                0xb92b,
                0x5af5,
                0x4ad4,
                0x7ab7,
                0x6a96,
                0x1a71,
                0x0a50,
                0x3a33,
                0x2a12,
                0xdbfd,
                0xcbdc,
                0xfbbf,
                0xeb9e,
                0x9b79,
                0x8b58,
                0xbb3b,
                0xab1a,
                0x6ca6,
                0x7c87,
                0x4ce4,
                0x5cc5,
                0x2c22,
                0x3c03,
                0x0c60,
                0x1c41,
                0xedae,
                0xfd8f,
                0xcdec,
                0xddcd,
                0xad2a,
                0xbd0b,
                0x8d68,
                0x9d49,
                0x7e97,
                0x6eb6,
                0x5ed5,
                0x4ef4,
                0x3e13,
                0x2e32,
                0x1e51,
                0x0e70,
                0xff9f,
                0xefbe,
                0xdfdd,
                0xcffc,
                0xbf1b,
                0xaf3a,
                0x9f59,
                0x8f78,
                0x9188,
                0x81a9,
                0xb1ca,
                0xa1eb,
                0xd10c,
                0xc12d,
                0xf14e,
                0xe16f,
                0x1080,
                0x00a1,
                0x30c2,
                0x20e3,
                0x5004,
                0x4025,
                0x7046,
                0x6067,
                0x83b9,
                0x9398,
                0xa3fb,
                0xb3da,
                0xc33d,
                0xd31c,
                0xe37f,
                0xf35e,
                0x02b1,
                0x1290,
                0x22f3,
                0x32d2,
                0x4235,
                0x5214,
                0x6277,
                0x7256,
                0xb5ea,
                0xa5cb,
                0x95a8,
                0x8589,
                0xf56e,
                0xe54f,
                0xd52c,
                0xc50d,
                0x34e2,
                0x24c3,
                0x14a0,
                0x0481,
                0x7466,
                0x6447,
                0x5424,
                0x4405,
                0xa7db,
                0xb7fa,
                0x8799,
                0x97b8,
                0xe75f,
                0xf77e,
                0xc71d,
                0xd73c,
                0x26d3,
                0x36f2,
                0x0691,
                0x16b0,
                0x6657,
                0x7676,
                0x4615,
                0x5634,
                0xd94c,
                0xc96d,
                0xf90e,
                0xe92f,
                0x99c8,
                0x89e9,
                0xb98a,
                0xa9ab,
                0x5844,
                0x4865,
                0x7806,
                0x6827,
                0x18c0,
                0x08e1,
                0x3882,
                0x28a3,
                0xcb7d,
                0xdb5c,
                0xeb3f,
                0xfb1e,
                0x8bf9,
                0x9bd8,
                0xabbb,
                0xbb9a,
                0x4a75,
                0x5a54,
                0x6a37,
                0x7a16,
                0x0af1,
                0x1ad0,
                0x2ab3,
                0x3a92,
                0xfd2e,
                0xed0f,
                0xdd6c,
                0xcd4d,
                0xbdaa,
                0xad8b,
                0x9de8,
                0x8dc9,
                0x7c26,
                0x6c07,
                0x5c64,
                0x4c45,
                0x3ca2,
                0x2c83,
                0x1ce0,
                0x0cc1,
                0xef1f,
                0xff3e,
                0xcf5d,
                0xdf7c,
                0xaf9b,
                0xbfba,
                0x8fd9,
                0x9ff8,
                0x6e17,
                0x7e36,
                0x4e55,
                0x5e74,
                0x2e93,
                0x3eb2,
                0x0ed1,
                0x1ef0,
            ]);
            crc16 = class crc16 {
                static checksum(data) {
                    let crc = 0;
                    for (let i = 0; i < data.byteLength; i++) {
                        let b = data[i];
                        crc = ((crc << 8) & 0xffff) ^ crc16tab[((crc >> 8) ^ (b)) & 0x00FF];
                    }
                    return crc;
                }
                static validate(data, expected) {
                    let ba = crc16.checksum(data);
                    return ba == expected;
                }
            };
            exports_29("crc16", crc16);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/base32", [], function (exports_30, context_30) {
    "use strict";
    var base32;
    var __moduleName = context_30 && context_30.id;
    return {
        setters: [],
        execute: function () {
            base32 = class base32 {
                static encode(src) {
                    let bits = 0;
                    let value = 0;
                    let a = new Uint8Array(src);
                    let buf = new Uint8Array(src.byteLength * 2);
                    let j = 0;
                    for (let i = 0; i < a.byteLength; i++) {
                        value = (value << 8) | a[i];
                        bits += 8;
                        while (bits >= 5) {
                            let index = (value >>> (bits - 5)) & 31;
                            buf[j++] = base32.alphabet.charAt(index).charCodeAt(0);
                            bits -= 5;
                        }
                    }
                    if (bits > 0) {
                        let index = (value << (5 - bits)) & 31;
                        buf[j++] = base32.alphabet.charAt(index).charCodeAt(0);
                    }
                    return buf.slice(0, j);
                }
                static decode(src) {
                    let bits = 0;
                    let byte = 0;
                    let j = 0;
                    let a = new Uint8Array(src);
                    let out = new Uint8Array(a.byteLength * 5 / 8 | 0);
                    for (let i = 0; i < a.byteLength; i++) {
                        let v = String.fromCharCode(a[i]);
                        let vv = base32.alphabet.indexOf(v);
                        if (vv === -1) {
                            throw new Error("Illegal Base32 character: " + a[i]);
                        }
                        byte = (byte << 5) | vv;
                        bits += 5;
                        if (bits >= 8) {
                            out[j++] = (byte >>> (bits - 8)) & 255;
                            bits -= 8;
                        }
                    }
                    return out.slice(0, j);
                }
            };
            exports_30("base32", base32);
            base32.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/codec", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/crc16", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/nkeys", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/base32"], function (exports_31, context_31) {
    "use strict";
    var crc16_ts_1, nkeys_ts_1, base32_ts_1, Codec;
    var __moduleName = context_31 && context_31.id;
    return {
        setters: [
            function (crc16_ts_1_1) {
                crc16_ts_1 = crc16_ts_1_1;
            },
            function (nkeys_ts_1_1) {
                nkeys_ts_1 = nkeys_ts_1_1;
            },
            function (base32_ts_1_1) {
                base32_ts_1 = base32_ts_1_1;
            }
        ],
        execute: function () {
            Codec = class Codec {
                static encode(prefix, src) {
                    if (!src || !(src instanceof Uint8Array)) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.SerializationError);
                    }
                    if (!nkeys_ts_1.Prefixes.isValidPrefix(prefix)) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidPrefixByte);
                    }
                    return Codec._encode(false, prefix, src);
                }
                static encodeSeed(role, src) {
                    if (!src) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.ApiError);
                    }
                    if (!nkeys_ts_1.Prefixes.isValidPublicPrefix(role)) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidPrefixByte);
                    }
                    if (src.byteLength !== 32) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidSeedLen);
                    }
                    return Codec._encode(true, role, src);
                }
                static decode(expected, src) {
                    if (!nkeys_ts_1.Prefixes.isValidPrefix(expected)) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidPrefixByte);
                    }
                    const raw = Codec._decode(src);
                    if (raw[0] !== expected) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidPrefixByte);
                    }
                    return raw.slice(1);
                }
                static decodeSeed(src) {
                    const raw = Codec._decode(src);
                    const prefix = Codec._decodePrefix(raw);
                    if (prefix[0] != nkeys_ts_1.Prefix.Seed) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidSeed);
                    }
                    if (!nkeys_ts_1.Prefixes.isValidPublicPrefix(prefix[1])) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidPrefixByte);
                    }
                    return ({ buf: raw.slice(2), prefix: prefix[1] });
                }
                static _encode(seed, role, payload) {
                    const payloadOffset = seed ? 2 : 1;
                    const payloadLen = payload.byteLength;
                    const checkLen = 2;
                    const cap = payloadOffset + payloadLen + checkLen;
                    const checkOffset = payloadOffset + payloadLen;
                    const raw = new Uint8Array(cap);
                    if (seed) {
                        const encodedPrefix = Codec._encodePrefix(nkeys_ts_1.Prefix.Seed, role);
                        raw.set(encodedPrefix);
                    }
                    else {
                        raw[0] = role;
                    }
                    raw.set(payload, payloadOffset);
                    const checksum = crc16_ts_1.crc16.checksum(raw.slice(0, checkOffset));
                    const dv = new DataView(raw.buffer);
                    dv.setUint16(checkOffset, checksum, true);
                    return base32_ts_1.base32.encode(raw);
                }
                static _decode(src) {
                    if (src.byteLength < 4) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidEncoding);
                    }
                    let raw;
                    try {
                        raw = base32_ts_1.base32.decode(src);
                    }
                    catch (ex) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidEncoding, ex);
                    }
                    const checkOffset = raw.byteLength - 2;
                    const dv = new DataView(raw.buffer);
                    const checksum = dv.getUint16(checkOffset, true);
                    const payload = raw.slice(0, checkOffset);
                    if (!crc16_ts_1.crc16.validate(payload, checksum)) {
                        throw new nkeys_ts_1.NKeysError(nkeys_ts_1.NKeysErrorCode.InvalidChecksum);
                    }
                    return payload;
                }
                static _encodePrefix(kind, role) {
                    const b1 = kind | (role >> 5);
                    const b2 = (role & 31) << 3;
                    return new Uint8Array([b1, b2]);
                }
                static _decodePrefix(raw) {
                    const b1 = raw[0] & 248;
                    const b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3);
                    return new Uint8Array([b1, b2]);
                }
            };
            exports_31("Codec", Codec);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/kp", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/codec", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/nkeys", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/helper"], function (exports_32, context_32) {
    "use strict";
    var codec_ts_1, nkeys_ts_2, helper_ts_1, KP;
    var __moduleName = context_32 && context_32.id;
    return {
        setters: [
            function (codec_ts_1_1) {
                codec_ts_1 = codec_ts_1_1;
            },
            function (nkeys_ts_2_1) {
                nkeys_ts_2 = nkeys_ts_2_1;
            },
            function (helper_ts_1_1) {
                helper_ts_1 = helper_ts_1_1;
            }
        ],
        execute: function () {
            KP = class KP {
                constructor(seed) {
                    this.seed = seed;
                }
                getRawSeed() {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    let sd = codec_ts_1.Codec.decodeSeed(this.seed);
                    return sd.buf;
                }
                getSeed() {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    return this.seed;
                }
                getPublicKey() {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    const sd = codec_ts_1.Codec.decodeSeed(this.seed);
                    const kp = helper_ts_1.getEd25519Helper().fromSeed(this.getRawSeed());
                    const buf = codec_ts_1.Codec.encode(sd.prefix, kp.publicKey);
                    return new TextDecoder().decode(buf);
                }
                getPrivateKey() {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    const kp = helper_ts_1.getEd25519Helper().fromSeed(this.getRawSeed());
                    return codec_ts_1.Codec.encode(nkeys_ts_2.Prefix.Private, kp.secretKey);
                }
                sign(input) {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    const kp = helper_ts_1.getEd25519Helper().fromSeed(this.getRawSeed());
                    return helper_ts_1.getEd25519Helper().sign(input, kp.secretKey);
                }
                verify(input, sig) {
                    if (!this.seed) {
                        throw new nkeys_ts_2.NKeysError(nkeys_ts_2.NKeysErrorCode.ClearedPair);
                    }
                    const kp = helper_ts_1.getEd25519Helper().fromSeed(this.getRawSeed());
                    return helper_ts_1.getEd25519Helper().verify(input, sig, kp.publicKey);
                }
                clear() {
                    if (!this.seed) {
                        return;
                    }
                    this.seed.fill(0);
                    this.seed = undefined;
                }
            };
            exports_32("KP", KP);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/public", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/codec", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/nkeys", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/helper"], function (exports_33, context_33) {
    "use strict";
    var codec_ts_2, nkeys_ts_3, helper_ts_2, PublicKey;
    var __moduleName = context_33 && context_33.id;
    return {
        setters: [
            function (codec_ts_2_1) {
                codec_ts_2 = codec_ts_2_1;
            },
            function (nkeys_ts_3_1) {
                nkeys_ts_3 = nkeys_ts_3_1;
            },
            function (helper_ts_2_1) {
                helper_ts_2 = helper_ts_2_1;
            }
        ],
        execute: function () {
            PublicKey = class PublicKey {
                constructor(publicKey) {
                    this.publicKey = publicKey;
                }
                getPublicKey() {
                    if (!this.publicKey) {
                        throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.ClearedPair);
                    }
                    return new TextDecoder().decode(this.publicKey);
                }
                getPrivateKey() {
                    if (!this.publicKey) {
                        throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.ClearedPair);
                    }
                    throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.PublicKeyOnly);
                }
                getSeed() {
                    if (!this.publicKey) {
                        throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.ClearedPair);
                    }
                    throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.PublicKeyOnly);
                }
                sign(_) {
                    if (!this.publicKey) {
                        throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.ClearedPair);
                    }
                    throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.CannotSign);
                }
                verify(input, sig) {
                    if (!this.publicKey) {
                        throw new nkeys_ts_3.NKeysError(nkeys_ts_3.NKeysErrorCode.ClearedPair);
                    }
                    let buf = codec_ts_2.Codec._decode(this.publicKey);
                    return helper_ts_2.getEd25519Helper().verify(input, sig, buf.slice(1));
                }
                clear() {
                    if (!this.publicKey) {
                        return;
                    }
                    this.publicKey.fill(0);
                    this.publicKey = undefined;
                }
            };
            exports_33("PublicKey", PublicKey);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/nkeys", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/kp", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/public", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/codec", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/helper"], function (exports_34, context_34) {
    "use strict";
    var kp_ts_1, public_ts_1, codec_ts_3, helper_ts_3, Prefix, Prefixes, NKeysErrorCode, NKeysError;
    var __moduleName = context_34 && context_34.id;
    function createPair(prefix) {
        const rawSeed = helper_ts_3.getEd25519Helper().randomBytes(32);
        let str = codec_ts_3.Codec.encodeSeed(prefix, new Uint8Array(rawSeed));
        return new kp_ts_1.KP(str);
    }
    exports_34("createPair", createPair);
    function createOperator() {
        return createPair(Prefix.Operator);
    }
    exports_34("createOperator", createOperator);
    function createAccount() {
        return createPair(Prefix.Account);
    }
    exports_34("createAccount", createAccount);
    function createUser() {
        return createPair(Prefix.User);
    }
    exports_34("createUser", createUser);
    function createCluster() {
        return createPair(Prefix.Cluster);
    }
    exports_34("createCluster", createCluster);
    function createServer() {
        return createPair(Prefix.Server);
    }
    exports_34("createServer", createServer);
    function fromPublic(src) {
        const ba = new TextEncoder().encode(src);
        const raw = codec_ts_3.Codec._decode(ba);
        const prefix = Prefixes.parsePrefix(raw[0]);
        if (Prefixes.isValidPublicPrefix(prefix)) {
            return new public_ts_1.PublicKey(ba);
        }
        throw new NKeysError(NKeysErrorCode.InvalidPublicKey);
    }
    exports_34("fromPublic", fromPublic);
    function fromSeed(src) {
        codec_ts_3.Codec.decodeSeed(src);
        return new kp_ts_1.KP(src);
    }
    exports_34("fromSeed", fromSeed);
    return {
        setters: [
            function (kp_ts_1_1) {
                kp_ts_1 = kp_ts_1_1;
            },
            function (public_ts_1_1) {
                public_ts_1 = public_ts_1_1;
            },
            function (codec_ts_3_1) {
                codec_ts_3 = codec_ts_3_1;
            },
            function (helper_ts_3_1) {
                helper_ts_3 = helper_ts_3_1;
            }
        ],
        execute: function () {
            (function (Prefix) {
                Prefix[Prefix["Seed"] = 144] = "Seed";
                Prefix[Prefix["Private"] = 120] = "Private";
                Prefix[Prefix["Operator"] = 112] = "Operator";
                Prefix[Prefix["Server"] = 104] = "Server";
                Prefix[Prefix["Cluster"] = 16] = "Cluster";
                Prefix[Prefix["Account"] = 0] = "Account";
                Prefix[Prefix["User"] = 160] = "User";
            })(Prefix || (Prefix = {}));
            exports_34("Prefix", Prefix);
            Prefixes = class Prefixes {
                static isValidPublicPrefix(prefix) {
                    return prefix == Prefix.Server ||
                        prefix == Prefix.Operator ||
                        prefix == Prefix.Cluster ||
                        prefix == Prefix.Account ||
                        prefix == Prefix.User;
                }
                static startsWithValidPrefix(s) {
                    let c = s[0];
                    return c == "S" || c == "P" || c == "O" || c == "N" || c == "C" ||
                        c == "A" || c == "U";
                }
                static isValidPrefix(prefix) {
                    let v = this.parsePrefix(prefix);
                    return v != -1;
                }
                static parsePrefix(v) {
                    switch (v) {
                        case Prefix.Seed:
                            return Prefix.Seed;
                        case Prefix.Private:
                            return Prefix.Private;
                        case Prefix.Operator:
                            return Prefix.Operator;
                        case Prefix.Server:
                            return Prefix.Server;
                        case Prefix.Cluster:
                            return Prefix.Cluster;
                        case Prefix.Account:
                            return Prefix.Account;
                        case Prefix.User:
                            return Prefix.User;
                        default:
                            return -1;
                    }
                }
            };
            exports_34("Prefixes", Prefixes);
            (function (NKeysErrorCode) {
                NKeysErrorCode["InvalidPrefixByte"] = "nkeys: invalid prefix byte";
                NKeysErrorCode["InvalidKey"] = "nkeys: invalid key";
                NKeysErrorCode["InvalidPublicKey"] = "nkeys: invalid public key";
                NKeysErrorCode["InvalidSeedLen"] = "nkeys: invalid seed length";
                NKeysErrorCode["InvalidSeed"] = "nkeys: invalid seed";
                NKeysErrorCode["InvalidEncoding"] = "nkeys: invalid encoded key";
                NKeysErrorCode["InvalidSignature"] = "nkeys: signature verification failed";
                NKeysErrorCode["CannotSign"] = "nkeys: cannot sign, no private key available";
                NKeysErrorCode["PublicKeyOnly"] = "nkeys: no seed or private key available";
                NKeysErrorCode["InvalidChecksum"] = "nkeys: invalid checksum";
                NKeysErrorCode["SerializationError"] = "nkeys: serialization error";
                NKeysErrorCode["ApiError"] = "nkeys: api error";
                NKeysErrorCode["ClearedPair"] = "nkeys: pair is cleared";
            })(NKeysErrorCode || (NKeysErrorCode = {}));
            exports_34("NKeysErrorCode", NKeysErrorCode);
            NKeysError = class NKeysError extends Error {
                constructor(code, chainedError) {
                    super(code);
                    this.name = "NKeysError";
                    this.code = code;
                    this.chainedError = chainedError;
                }
            };
            exports_34("NKeysError", NKeysError);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/util", [], function (exports_35, context_35) {
    "use strict";
    var __moduleName = context_35 && context_35.id;
    function encode(bytes) {
        return btoa(String.fromCharCode(...bytes));
    }
    exports_35("encode", encode);
    function decode(b64str) {
        const bin = atob(b64str);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        return bytes;
    }
    exports_35("decode", decode);
    function dump(buf, msg) {
        if (msg) {
            console.log(msg);
        }
        let a = [];
        for (let i = 0; i < buf.byteLength; i++) {
            if (i % 8 === 0) {
                a.push("\n");
            }
            let v = buf[i].toString(16);
            if (v.length === 1) {
                v = "0" + v;
            }
            a.push(v);
        }
        console.log(a.join("  "));
    }
    exports_35("dump", dump);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/mod", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/nkeys", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/util"], function (exports_36, context_36) {
    "use strict";
    var __moduleName = context_36 && context_36.id;
    return {
        setters: [
            function (nkeys_ts_4_1) {
                exports_36({
                    "createPair": nkeys_ts_4_1["createPair"],
                    "createAccount": nkeys_ts_4_1["createAccount"],
                    "createUser": nkeys_ts_4_1["createUser"],
                    "createOperator": nkeys_ts_4_1["createOperator"],
                    "fromPublic": nkeys_ts_4_1["fromPublic"],
                    "fromSeed": nkeys_ts_4_1["fromSeed"],
                    "NKeysError": nkeys_ts_4_1["NKeysError"],
                    "NKeysErrorCode": nkeys_ts_4_1["NKeysErrorCode"]
                });
            },
            function (util_ts_1_1) {
                exports_36({
                    "encode": util_ts_1_1["encode"],
                    "decode": util_ts_1_1["decode"]
                });
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/modules/esm/mod", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/modules/esm/deps", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/helper", "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/src/mod"], function (exports_37, context_37) {
    "use strict";
    var deps_ts_1, helper_ts_4;
    var __moduleName = context_37 && context_37.id;
    function exportStar_3(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default") exports[n] = m[n];
        }
        exports_37(exports);
    }
    return {
        setters: [
            function (deps_ts_1_1) {
                deps_ts_1 = deps_ts_1_1;
            },
            function (helper_ts_4_1) {
                helper_ts_4 = helper_ts_4_1;
            },
            function (mod_ts_1_1) {
                exportStar_3(mod_ts_1_1);
            }
        ],
        execute: function () {
            helper_ts_4.setEd25519Helper(deps_ts_1.denoHelper);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nkeys", ["https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-7/modules/esm/mod"], function (exports_38, context_38) {
    "use strict";
    var __moduleName = context_38 && context_38.id;
    return {
        setters: [
            function (nkeys_1) {
                exports_38("nkeys", nkeys_1);
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/mod", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/internal_mod"], function (exports_39, context_39) {
    "use strict";
    var __moduleName = context_39 && context_39.id;
    return {
        setters: [
            function (internal_mod_ts_1_1) {
                exports_39({
                    "Bench": internal_mod_ts_1_1["Bench"],
                    "ErrorCode": internal_mod_ts_1_1["ErrorCode"],
                    "NatsError": internal_mod_ts_1_1["NatsError"],
                    "Empty": internal_mod_ts_1_1["Empty"],
                    "Events": internal_mod_ts_1_1["Events"],
                    "createInbox": internal_mod_ts_1_1["createInbox"],
                    "credsAuthenticator": internal_mod_ts_1_1["credsAuthenticator"],
                    "headers": internal_mod_ts_1_1["headers"],
                    "JSONCodec": internal_mod_ts_1_1["JSONCodec"],
                    "jwtAuthenticator": internal_mod_ts_1_1["jwtAuthenticator"],
                    "nkeyAuthenticator": internal_mod_ts_1_1["nkeyAuthenticator"],
                    "Nuid": internal_mod_ts_1_1["Nuid"],
                    "StringCodec": internal_mod_ts_1_1["StringCodec"]
                });
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/authenticator", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nkeys", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/mod", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_40, context_40) {
    "use strict";
    var nkeys_ts_5, mod_ts_2, encoders_ts_2;
    var __moduleName = context_40 && context_40.id;
    function buildAuthenticator(opts) {
        if (opts.authenticator) {
            return opts.authenticator;
        }
        if (opts.token) {
            return tokenFn(opts.token);
        }
        if (opts.user) {
            return passFn(opts.user, opts.pass);
        }
        return noAuthFn();
    }
    exports_40("buildAuthenticator", buildAuthenticator);
    function noAuthFn() {
        return () => {
            return;
        };
    }
    exports_40("noAuthFn", noAuthFn);
    function passFn(user, pass) {
        return () => {
            return { user, pass };
        };
    }
    function tokenFn(token) {
        return () => {
            return { auth_token: token };
        };
    }
    function nkeyAuthenticator(seed) {
        return (nonce) => {
            seed = typeof seed === "function" ? seed() : seed;
            const kp = seed ? nkeys_ts_5.nkeys.fromSeed(seed) : undefined;
            const nkey = kp ? kp.getPublicKey() : "";
            const challenge = encoders_ts_2.TE.encode(nonce || "");
            const sigBytes = kp !== undefined && nonce ? kp.sign(challenge) : undefined;
            const sig = sigBytes ? nkeys_ts_5.nkeys.encode(sigBytes) : "";
            return { nkey, sig };
        };
    }
    exports_40("nkeyAuthenticator", nkeyAuthenticator);
    function jwtAuthenticator(ajwt, seed) {
        return (nonce) => {
            const jwt = typeof ajwt === "function" ? ajwt() : ajwt;
            const fn = nkeyAuthenticator(seed);
            const { nkey, sig } = fn(nonce);
            return { jwt, nkey, sig };
        };
    }
    exports_40("jwtAuthenticator", jwtAuthenticator);
    function credsAuthenticator(creds) {
        const CREDS = /\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))/ig;
        const s = encoders_ts_2.TD.decode(creds);
        let m = CREDS.exec(s);
        if (!m) {
            throw mod_ts_2.NatsError.errorForCode(mod_ts_2.ErrorCode.BAD_CREDS);
        }
        const jwt = m[1].trim();
        m = CREDS.exec(s);
        if (!m) {
            throw mod_ts_2.NatsError.errorForCode(mod_ts_2.ErrorCode.BAD_CREDS);
        }
        const seed = encoders_ts_2.TE.encode(m[1].trim());
        return jwtAuthenticator(jwt, seed);
    }
    exports_40("credsAuthenticator", credsAuthenticator);
    return {
        setters: [
            function (nkeys_ts_5_1) {
                nkeys_ts_5 = nkeys_ts_5_1;
            },
            function (mod_ts_2_1) {
                mod_ts_2 = mod_ts_2_1;
            },
            function (encoders_ts_2_1) {
                encoders_ts_2 = encoders_ts_2_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", [], function (exports_41, context_41) {
    "use strict";
    var Empty, Events, DebugEvents, DEFAULT_PORT, DEFAULT_HOST, DEFAULT_HOSTPORT, DEFAULT_RECONNECT_TIME_WAIT, DEFAULT_MAX_RECONNECT_ATTEMPTS, DEFAULT_JITTER, DEFAULT_JITTER_TLS, DEFAULT_PING_INTERVAL, DEFAULT_MAX_PING_OUT;
    var __moduleName = context_41 && context_41.id;
    return {
        setters: [],
        execute: function () {
            exports_41("Empty", Empty = new Uint8Array(0));
            exports_41("Events", Events = Object.freeze({
                DISCONNECT: "disconnect",
                RECONNECT: "reconnect",
                UPDATE: "update",
                LDM: "ldm",
            }));
            exports_41("DebugEvents", DebugEvents = Object.freeze({
                RECONNECTING: "reconnecting",
                PING_TIMER: "pingTimer",
                STALE_CONNECTION: "staleConnection",
            }));
            exports_41("DEFAULT_PORT", DEFAULT_PORT = 4222);
            exports_41("DEFAULT_HOST", DEFAULT_HOST = "127.0.0.1");
            exports_41("DEFAULT_HOSTPORT", DEFAULT_HOSTPORT = `${DEFAULT_HOST}:${DEFAULT_PORT}`);
            exports_41("DEFAULT_RECONNECT_TIME_WAIT", DEFAULT_RECONNECT_TIME_WAIT = 2 * 1000);
            exports_41("DEFAULT_MAX_RECONNECT_ATTEMPTS", DEFAULT_MAX_RECONNECT_ATTEMPTS = 10);
            exports_41("DEFAULT_JITTER", DEFAULT_JITTER = 100);
            exports_41("DEFAULT_JITTER_TLS", DEFAULT_JITTER_TLS = 1000);
            exports_41("DEFAULT_PING_INTERVAL", DEFAULT_PING_INTERVAL = 2 * 60 * 1000);
            exports_41("DEFAULT_MAX_PING_OUT", DEFAULT_MAX_PING_OUT = 2);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types"], function (exports_42, context_42) {
    "use strict";
    var types_ts_1, TE, TD;
    var __moduleName = context_42 && context_42.id;
    function fastEncoder(...a) {
        let len = 0;
        for (let i = 0; i < a.length; i++) {
            len += a[i] ? a[i].length : 0;
        }
        if (len === 0) {
            return types_ts_1.Empty;
        }
        const buf = new Uint8Array(len);
        let c = 0;
        for (let i = 0; i < a.length; i++) {
            const s = a[i];
            if (s) {
                for (let j = 0; j < s.length; j++) {
                    buf[c] = s.charCodeAt(j);
                    c++;
                }
            }
        }
        return buf;
    }
    exports_42("fastEncoder", fastEncoder);
    function fastDecoder(a) {
        if (!a || a.length === 0) {
            return "";
        }
        return String.fromCharCode(...a);
    }
    exports_42("fastDecoder", fastDecoder);
    return {
        setters: [
            function (types_ts_1_1) {
                types_ts_1 = types_ts_1_1;
            }
        ],
        execute: function () {
            exports_42("TE", TE = new TextEncoder());
            exports_42("TD", TD = new TextDecoder());
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/databuffer", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_43, context_43) {
    "use strict";
    var encoders_ts_3, DataBuffer;
    var __moduleName = context_43 && context_43.id;
    return {
        setters: [
            function (encoders_ts_3_1) {
                encoders_ts_3 = encoders_ts_3_1;
            }
        ],
        execute: function () {
            DataBuffer = class DataBuffer {
                constructor() {
                    this.buffers = [];
                    this.byteLength = 0;
                }
                static concat(...bufs) {
                    let max = 0;
                    for (let i = 0; i < bufs.length; i++) {
                        max += bufs[i].length;
                    }
                    let out = new Uint8Array(max);
                    let index = 0;
                    for (let i = 0; i < bufs.length; i++) {
                        out.set(bufs[i], index);
                        index += bufs[i].length;
                    }
                    return out;
                }
                static fromAscii(m) {
                    if (!m) {
                        m = "";
                    }
                    return encoders_ts_3.TE.encode(m);
                }
                static toAscii(a) {
                    return encoders_ts_3.TD.decode(a);
                }
                reset() {
                    this.buffers.length = 0;
                    this.byteLength = 0;
                }
                pack() {
                    if (this.buffers.length > 1) {
                        let v = new Uint8Array(this.byteLength);
                        let index = 0;
                        for (let i = 0; i < this.buffers.length; i++) {
                            v.set(this.buffers[i], index);
                            index += this.buffers[i].length;
                        }
                        this.buffers.length = 0;
                        this.buffers.push(v);
                    }
                }
                drain(n) {
                    if (this.buffers.length) {
                        this.pack();
                        let v = this.buffers.pop();
                        if (v) {
                            let max = this.byteLength;
                            if (n === undefined || n > max) {
                                n = max;
                            }
                            let d = v.subarray(0, n);
                            if (max > n) {
                                this.buffers.push(v.subarray(n));
                            }
                            this.byteLength = max - n;
                            return d;
                        }
                    }
                    return new Uint8Array(0);
                }
                fill(a, ...bufs) {
                    if (a) {
                        this.buffers.push(a);
                        this.byteLength += a.length;
                    }
                    for (let i = 0; i < bufs.length; i++) {
                        if (bufs[i] && bufs[i].length) {
                            this.buffers.push(bufs[i]);
                            this.byteLength += bufs[i].length;
                        }
                    }
                }
                peek() {
                    if (this.buffers.length) {
                        this.pack();
                        return this.buffers[0];
                    }
                    return new Uint8Array(0);
                }
                size() {
                    return this.byteLength;
                }
                length() {
                    return this.buffers.length;
                }
            };
            exports_43("DataBuffer", DataBuffer);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/databuffer", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_44, context_44) {
    "use strict";
    var databuffer_ts_1, error_ts_2, encoders_ts_4, CR_LF, CR_LF_LEN, CRLF, CR, LF, Perf;
    var __moduleName = context_44 && context_44.id;
    function isUint8Array(a) {
        return a instanceof Uint8Array;
    }
    exports_44("isUint8Array", isUint8Array);
    function protoLen(ba) {
        for (let i = 0; i < ba.length; i++) {
            let n = i + 1;
            if (ba.byteLength > n && ba[i] === CR && ba[n] === LF) {
                return n + 1;
            }
        }
        return -1;
    }
    exports_44("protoLen", protoLen);
    function extractProtocolMessage(a) {
        let len = protoLen(a);
        if (len) {
            let ba = new Uint8Array(a);
            let out = ba.slice(0, len);
            return encoders_ts_4.TD.decode(out);
        }
        return "";
    }
    exports_44("extractProtocolMessage", extractProtocolMessage);
    function extend(a, ...b) {
        for (let i = 0; i < b.length; i++) {
            let o = b[i];
            Object.keys(o).forEach(function (k) {
                a[k] = o[k];
            });
        }
        return a;
    }
    exports_44("extend", extend);
    function settle(a) {
        if (Array.isArray(a)) {
            return Promise.resolve(a).then(_settle);
        }
        else {
            return Promise.reject(new TypeError("argument requires an array of promises"));
        }
    }
    exports_44("settle", settle);
    function _settle(a) {
        return Promise.all(a.map((p) => {
            return Promise.resolve(p).then(_resolve, _resolve);
        }));
    }
    function _resolve(r) {
        return r;
    }
    function pending() {
        const v = {};
        const promise = new Promise((resolve) => {
            v.promise = () => {
                return promise;
            };
            v.write = (c) => {
                if (v.resolved) {
                    return;
                }
                v.pending += c;
            };
            v.wrote = (c) => {
                if (v.resolved) {
                    return;
                }
                v.pending -= c;
                if (v.done && 0 >= v.pending) {
                    resolve();
                }
            };
            v.close = () => {
                v.done = true;
                if (v.pending === 0) {
                    resolve();
                }
            };
            v.err = () => {
                v.pending = 0;
                v.resolved = true;
                v.close();
            };
        });
        return v;
    }
    exports_44("pending", pending);
    function render(frame) {
        const cr = "␍";
        const lf = "␊";
        return encoders_ts_4.TD.decode(frame)
            .replace(/\n/g, lf)
            .replace(/\r/g, cr);
    }
    exports_44("render", render);
    function timeout(ms) {
        let methods;
        let timer;
        const p = new Promise((resolve, reject) => {
            let cancel = () => {
                if (timer) {
                    clearTimeout(timer);
                }
            };
            methods = { cancel };
            timer = setTimeout(() => {
                reject(error_ts_2.NatsError.errorForCode(error_ts_2.ErrorCode.TIMEOUT));
            }, ms);
        });
        return Object.assign(p, methods);
    }
    exports_44("timeout", timeout);
    function delay(ms = 0, value) {
        return new Promise((resolve) => {
            setTimeout(() => {
                resolve(value);
            }, ms);
        });
    }
    exports_44("delay", delay);
    function deferred() {
        let methods = {};
        const p = new Promise((resolve, reject) => {
            methods = { resolve, reject };
        });
        return Object.assign(p, methods);
    }
    exports_44("deferred", deferred);
    function shuffle(a) {
        for (let i = a.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
    }
    exports_44("shuffle", shuffle);
    return {
        setters: [
            function (databuffer_ts_1_1) {
                databuffer_ts_1 = databuffer_ts_1_1;
            },
            function (error_ts_2_1) {
                error_ts_2 = error_ts_2_1;
            },
            function (encoders_ts_4_1) {
                encoders_ts_4 = encoders_ts_4_1;
            }
        ],
        execute: function () {
            exports_44("CR_LF", CR_LF = "\r\n");
            exports_44("CR_LF_LEN", CR_LF_LEN = CR_LF.length);
            exports_44("CRLF", CRLF = databuffer_ts_1.DataBuffer.fromAscii(CR_LF));
            exports_44("CR", CR = new Uint8Array(CRLF)[0]);
            exports_44("LF", LF = new Uint8Array(CRLF)[1]);
            Perf = class Perf {
                constructor() {
                    this.timers = new Map();
                    this.measures = new Map();
                }
                mark(key) {
                    this.timers.set(key, Date.now());
                }
                measure(key, startKey, endKey) {
                    const s = this.timers.get(startKey);
                    if (s === undefined) {
                        throw new Error(`${startKey} is not defined`);
                    }
                    const e = this.timers.get(endKey);
                    if (e === undefined) {
                        throw new Error(`${endKey} is not defined`);
                    }
                    this.measures.set(key, e - s);
                }
                getEntries() {
                    const values = [];
                    this.measures.forEach((v, k) => {
                        values.push({ name: k, duration: v });
                    });
                    return values;
                }
            };
            exports_44("Perf", Perf);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/transport", [], function (exports_45, context_45) {
    "use strict";
    var transportFactory;
    var __moduleName = context_45 && context_45.id;
    function setTransportFactory(fn) {
        transportFactory = fn;
    }
    exports_45("setTransportFactory", setTransportFactory);
    function newTransport() {
        if (typeof transportFactory !== "function") {
            throw new Error("transport is not set");
        }
        return transportFactory();
    }
    exports_45("newTransport", newTransport);
    return {
        setters: [],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nuid", [], function (exports_46, context_46) {
    "use strict";
    var digits, base, preLen, seqLen, maxSeq, minInc, maxInc, totalLen, cryptoObj, Nuid, nuid;
    var __moduleName = context_46 && context_46.id;
    function initCrypto() {
        let cryptoObj = null;
        if (typeof globalThis !== "undefined") {
            if ("crypto" in globalThis && globalThis.crypto.getRandomValues) {
                cryptoObj = globalThis.crypto;
            }
        }
        if (!cryptoObj) {
            cryptoObj = {
                getRandomValues: function (array) {
                    for (let i = 0; i < array.length; i++) {
                        array[i] = Math.floor(Math.random() * 255);
                    }
                },
            };
        }
        return cryptoObj;
    }
    return {
        setters: [],
        execute: function () {
            digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            base = 36;
            preLen = 12;
            seqLen = 10;
            maxSeq = 3656158440062976;
            minInc = 33;
            maxInc = 333;
            totalLen = preLen + seqLen;
            cryptoObj = initCrypto();
            Nuid = class Nuid {
                constructor() {
                    this.buf = new Uint8Array(totalLen);
                    this.init();
                }
                init() {
                    this.setPre();
                    this.initSeqAndInc();
                    this.fillSeq();
                }
                initSeqAndInc() {
                    this.seq = Math.floor(Math.random() * maxSeq);
                    this.inc = Math.floor(Math.random() * (maxInc - minInc) + minInc);
                }
                setPre() {
                    let cbuf = new Uint8Array(preLen);
                    cryptoObj.getRandomValues(cbuf);
                    for (let i = 0; i < preLen; i++) {
                        let di = cbuf[i] % base;
                        this.buf[i] = digits.charCodeAt(di);
                    }
                }
                fillSeq() {
                    let n = this.seq;
                    for (let i = totalLen - 1; i >= preLen; i--) {
                        this.buf[i] = digits.charCodeAt(n % base);
                        n = Math.floor(n / base);
                    }
                }
                next() {
                    this.seq += this.inc;
                    if (this.seq > maxSeq) {
                        this.setPre();
                        this.initSeqAndInc();
                    }
                    this.fillSeq();
                    return String.fromCharCode.apply(String, this.buf);
                }
                reset() {
                    this.init();
                }
            };
            exports_46("Nuid", Nuid);
            exports_46("nuid", nuid = new Nuid());
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/servers", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util"], function (exports_47, context_47) {
    "use strict";
    var types_ts_2, util_ts_2, Server, Servers;
    var __moduleName = context_47 && context_47.id;
    return {
        setters: [
            function (types_ts_2_1) {
                types_ts_2 = types_ts_2_1;
            },
            function (util_ts_2_1) {
                util_ts_2 = util_ts_2_1;
            }
        ],
        execute: function () {
            Server = class Server {
                constructor(u, gossiped = false) {
                    if (u.match(/^(.*:\/\/)(.*)/m)) {
                        u = u.replace(/^(.*:\/\/)(.*)/gm, "$2");
                    }
                    let url = new URL(`http://${u}`);
                    if (!url.port) {
                        url.port = `${types_ts_2.DEFAULT_PORT}`;
                    }
                    this.listen = url.host;
                    this.hostname = url.hostname;
                    this.port = parseInt(url.port, 10);
                    this.didConnect = false;
                    this.reconnects = 0;
                    this.lastConnect = 0;
                    this.gossiped = gossiped;
                }
                toString() {
                    return this.listen;
                }
                hostport() {
                    return this;
                }
            };
            exports_47("Server", Server);
            Servers = class Servers {
                constructor(randomize, listens = [], firstServer) {
                    this.firstSelect = true;
                    this.servers = [];
                    if (listens) {
                        listens.forEach((hp) => {
                            this.servers.push(new Server(hp));
                        });
                        if (randomize) {
                            this.servers = util_ts_2.shuffle(this.servers);
                        }
                    }
                    if (firstServer) {
                        let index = listens.indexOf(firstServer);
                        if (index === -1) {
                            this.servers.unshift(new Server(firstServer));
                        }
                        else {
                            let fs = this.servers[index];
                            this.servers.splice(index, 1);
                            this.servers.unshift(fs);
                        }
                    }
                    else {
                        if (this.servers.length === 0) {
                            this.addServer(types_ts_2.DEFAULT_HOSTPORT, false);
                        }
                    }
                    this.currentServer = this.servers[0];
                }
                getCurrentServer() {
                    return this.currentServer;
                }
                addServer(u, implicit = false) {
                    this.servers.push(new Server(u, implicit));
                }
                selectServer() {
                    if (this.firstSelect) {
                        this.firstSelect = false;
                        return this.currentServer;
                    }
                    let t = this.servers.shift();
                    if (t) {
                        this.servers.push(t);
                        this.currentServer = t;
                    }
                    return t;
                }
                removeCurrentServer() {
                    this.removeServer(this.currentServer);
                }
                removeServer(server) {
                    if (server) {
                        let index = this.servers.indexOf(server);
                        this.servers.splice(index, 1);
                    }
                }
                length() {
                    return this.servers.length;
                }
                next() {
                    return this.servers.length ? this.servers[0] : undefined;
                }
                getServers() {
                    return this.servers;
                }
                update(info) {
                    const added = [];
                    let deleted = [];
                    const discovered = new Map();
                    if (info.connect_urls && info.connect_urls.length > 0) {
                        info.connect_urls.forEach((hp) => {
                            discovered.set(hp, new Server(hp, true));
                        });
                    }
                    let toDelete = [];
                    this.servers.forEach((s, index) => {
                        let u = s.listen;
                        if (s.gossiped && this.currentServer.listen !== u &&
                            discovered.get(u) === undefined) {
                            toDelete.push(index);
                        }
                        discovered.delete(u);
                    });
                    toDelete.reverse();
                    toDelete.forEach((index) => {
                        let removed = this.servers.splice(index, 1);
                        deleted = deleted.concat(removed[0].listen);
                    });
                    discovered.forEach((v, k, m) => {
                        this.servers.push(v);
                        added.push(k);
                    });
                    return { added, deleted };
                }
            };
            exports_47("Servers", Servers);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/queued_iterator", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error"], function (exports_48, context_48) {
    "use strict";
    var util_ts_3, error_ts_3, QueuedIterator;
    var __moduleName = context_48 && context_48.id;
    return {
        setters: [
            function (util_ts_3_1) {
                util_ts_3 = util_ts_3_1;
            },
            function (error_ts_3_1) {
                error_ts_3 = error_ts_3_1;
            }
        ],
        execute: function () {
            QueuedIterator = class QueuedIterator {
                constructor() {
                    this.inflight = 0;
                    this.processed = 0;
                    this.received = 0;
                    this.noIterator = false;
                    this.done = false;
                    this.signal = util_ts_3.deferred();
                    this.yields = [];
                }
                [Symbol.asyncIterator]() {
                    return this.iterate();
                }
                push(v) {
                    if (this.done) {
                        return;
                    }
                    this.yields.push(v);
                    this.signal.resolve();
                }
                async *iterate() {
                    if (this.noIterator) {
                        throw new error_ts_3.NatsError("unsupported iterator", error_ts_3.ErrorCode.API_ERROR);
                    }
                    while (true) {
                        if (this.yields.length === 0) {
                            await this.signal;
                        }
                        if (this.err) {
                            throw this.err;
                        }
                        const yields = this.yields;
                        this.inflight = yields.length;
                        this.yields = [];
                        for (let i = 0; i < yields.length; i++) {
                            this.processed++;
                            yield yields[i];
                            this.inflight--;
                        }
                        if (this.done) {
                            break;
                        }
                        else if (this.yields.length === 0) {
                            yields.length = 0;
                            this.yields = yields;
                            this.signal = util_ts_3.deferred();
                        }
                    }
                }
                stop(err) {
                    this.err = err;
                    this.done = true;
                    this.signal.resolve();
                }
                getProcessed() {
                    return this.noIterator ? this.received : this.processed;
                }
                getPending() {
                    return this.yields.length + this.inflight;
                }
                getReceived() {
                    return this.received;
                }
            };
            exports_48("QueuedIterator", QueuedIterator);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscription", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/queued_iterator", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error"], function (exports_49, context_49) {
    "use strict";
    var queued_iterator_ts_1, util_ts_4, error_ts_4, SubscriptionImpl;
    var __moduleName = context_49 && context_49.id;
    return {
        setters: [
            function (queued_iterator_ts_1_1) {
                queued_iterator_ts_1 = queued_iterator_ts_1_1;
            },
            function (util_ts_4_1) {
                util_ts_4 = util_ts_4_1;
            },
            function (error_ts_4_1) {
                error_ts_4 = error_ts_4_1;
            }
        ],
        execute: function () {
            SubscriptionImpl = class SubscriptionImpl extends queued_iterator_ts_1.QueuedIterator {
                constructor(protocol, subject, opts = {}) {
                    super();
                    this.draining = false;
                    util_ts_4.extend(this, opts);
                    this.protocol = protocol;
                    this.subject = subject;
                    this.noIterator = typeof opts.callback === "function";
                    if (opts.timeout) {
                        this.timer = util_ts_4.timeout(opts.timeout);
                        this.timer
                            .then(() => {
                            this.timer = undefined;
                        })
                            .catch((err) => {
                            this.stop(err);
                        });
                    }
                }
                callback(err, msg) {
                    this.cancelTimeout();
                    err ? this.stop(err) : this.push(msg);
                }
                close() {
                    if (!this.isClosed()) {
                        this.cancelTimeout();
                        this.stop();
                    }
                }
                unsubscribe(max) {
                    this.protocol.unsubscribe(this, max);
                }
                cancelTimeout() {
                    if (this.timer) {
                        this.timer.cancel();
                        this.timer = undefined;
                    }
                }
                drain() {
                    if (this.protocol.isClosed()) {
                        throw error_ts_4.NatsError.errorForCode(error_ts_4.ErrorCode.CONNECTION_CLOSED);
                    }
                    if (this.isClosed()) {
                        throw error_ts_4.NatsError.errorForCode(error_ts_4.ErrorCode.SUB_CLOSED);
                    }
                    if (!this.drained) {
                        this.protocol.unsub(this);
                        this.drained = this.protocol.flush(util_ts_4.deferred());
                        this.drained.then(() => {
                            this.protocol.subscriptions.cancel(this);
                        });
                    }
                    return this.drained;
                }
                isDraining() {
                    return this.draining;
                }
                isClosed() {
                    return this.done;
                }
                getSubject() {
                    return this.subject;
                }
                getMax() {
                    return this.max;
                }
                getID() {
                    return this.sid;
                }
            };
            exports_49("SubscriptionImpl", SubscriptionImpl);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscriptions", [], function (exports_50, context_50) {
    "use strict";
    var Subscriptions;
    var __moduleName = context_50 && context_50.id;
    return {
        setters: [],
        execute: function () {
            Subscriptions = class Subscriptions {
                constructor() {
                    this.subs = new Map();
                    this.sidCounter = 0;
                }
                size() {
                    return this.subs.size;
                }
                add(s) {
                    this.sidCounter++;
                    s.sid = this.sidCounter;
                    this.subs.set(s.sid, s);
                    return s;
                }
                setMux(s) {
                    this.mux = s;
                    return s;
                }
                getMux() {
                    return this.mux;
                }
                get(sid) {
                    return this.subs.get(sid);
                }
                all() {
                    let buf = [];
                    for (let s of this.subs.values()) {
                        buf.push(s);
                    }
                    return buf;
                }
                cancel(s) {
                    if (s) {
                        s.close();
                        this.subs.delete(s.sid);
                    }
                }
                handleError(err) {
                    if (err) {
                        const re = /^'Permissions Violation for Subscription to "(\S+)"'/i;
                        const ma = re.exec(err.message);
                        if (ma) {
                            const subj = ma[1];
                            this.subs.forEach((sub) => {
                                if (subj == sub.subject) {
                                    sub.callback(err, {});
                                    sub.close();
                                }
                            });
                        }
                    }
                }
                close() {
                    this.subs.forEach((sub) => {
                        sub.close();
                    });
                }
            };
            exports_50("Subscriptions", Subscriptions);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/request", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nuid"], function (exports_51, context_51) {
    "use strict";
    var util_ts_5, error_ts_5, nuid_ts_1, Request;
    var __moduleName = context_51 && context_51.id;
    return {
        setters: [
            function (util_ts_5_1) {
                util_ts_5 = util_ts_5_1;
            },
            function (error_ts_5_1) {
                error_ts_5 = error_ts_5_1;
            },
            function (nuid_ts_1_1) {
                nuid_ts_1 = nuid_ts_1_1;
            }
        ],
        execute: function () {
            Request = class Request {
                constructor(mux, opts = { timeout: 1000 }) {
                    this.received = 0;
                    this.deferred = util_ts_5.deferred();
                    this.mux = mux;
                    this.token = nuid_ts_1.nuid.next();
                    util_ts_5.extend(this, opts);
                    this.timer = util_ts_5.timeout(opts.timeout);
                }
                resolver(err, msg) {
                    if (this.timer) {
                        this.timer.cancel();
                    }
                    if (err) {
                        this.deferred.reject(err);
                    }
                    else {
                        this.deferred.resolve(msg);
                    }
                    this.cancel();
                }
                cancel(err) {
                    if (this.timer) {
                        this.timer.cancel();
                    }
                    this.mux.cancel(this);
                    this.deferred.reject(err ? err : error_ts_5.NatsError.errorForCode(error_ts_5.ErrorCode.CANCELLED));
                }
            };
            exports_51("Request", Request);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/muxsubscription", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/protocol"], function (exports_52, context_52) {
    "use strict";
    var error_ts_6, protocol_ts_1, MuxSubscription;
    var __moduleName = context_52 && context_52.id;
    return {
        setters: [
            function (error_ts_6_1) {
                error_ts_6 = error_ts_6_1;
            },
            function (protocol_ts_1_1) {
                protocol_ts_1 = protocol_ts_1_1;
            }
        ],
        execute: function () {
            MuxSubscription = class MuxSubscription {
                constructor() {
                    this.reqs = new Map();
                }
                size() {
                    return this.reqs.size;
                }
                init() {
                    this.baseInbox = `${protocol_ts_1.createInbox()}.`;
                    return this.baseInbox;
                }
                add(r) {
                    if (!isNaN(r.received)) {
                        r.received = 0;
                    }
                    this.reqs.set(r.token, r);
                }
                get(token) {
                    return this.reqs.get(token);
                }
                cancel(r) {
                    this.reqs.delete(r.token);
                }
                getToken(m) {
                    let s = m.subject || "";
                    if (s.indexOf(this.baseInbox) === 0) {
                        return s.substring(this.baseInbox.length);
                    }
                    return null;
                }
                dispatcher() {
                    return (err, m) => {
                        let token = this.getToken(m);
                        if (token) {
                            let r = this.get(token);
                            if (r) {
                                if (err === null && m.headers) {
                                    const headers = m.headers;
                                    if (headers.error) {
                                        err = new error_ts_6.NatsError(headers.error.toString(), error_ts_6.ErrorCode.REQUEST_ERROR);
                                    }
                                }
                                r.resolver(err, m);
                            }
                        }
                    };
                }
                close() {
                    const err = error_ts_6.NatsError.errorForCode(error_ts_6.ErrorCode.TIMEOUT);
                    this.reqs.forEach((req) => {
                        req.resolver(err, {});
                    });
                }
            };
            exports_52("MuxSubscription", MuxSubscription);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/heartbeats", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types"], function (exports_53, context_53) {
    "use strict";
    var util_ts_6, types_ts_3, Heartbeat;
    var __moduleName = context_53 && context_53.id;
    return {
        setters: [
            function (util_ts_6_1) {
                util_ts_6 = util_ts_6_1;
            },
            function (types_ts_3_1) {
                types_ts_3 = types_ts_3_1;
            }
        ],
        execute: function () {
            Heartbeat = class Heartbeat {
                constructor(ph, interval, maxOut) {
                    this.pendings = [];
                    this.ph = ph;
                    this.interval = interval;
                    this.maxOut = maxOut;
                }
                start() {
                    this.cancel();
                    this._schedule();
                }
                cancel(stale) {
                    if (this.timer) {
                        clearTimeout(this.timer);
                        this.timer = undefined;
                    }
                    this._reset();
                    if (stale) {
                        this.ph.disconnect();
                    }
                }
                _schedule() {
                    this.timer = setTimeout(() => {
                        this.ph.dispatchStatus({ type: types_ts_3.DebugEvents.PING_TIMER, data: `${this.pendings.length + 1}` });
                        if (this.pendings.length === this.maxOut) {
                            this.cancel(true);
                            return;
                        }
                        const ping = util_ts_6.deferred();
                        this.ph.flush(ping)
                            .then(() => {
                            this._reset();
                        })
                            .catch(() => {
                            this.cancel();
                        });
                        this.pendings.push(ping);
                        this._schedule();
                    }, this.interval);
                }
                _reset() {
                    this.pendings = this.pendings.filter((p) => {
                        const d = p;
                        d.resolve();
                        return false;
                    });
                }
            };
            exports_53("Heartbeat", Heartbeat);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/denobuffer", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_54, context_54) {
    "use strict";
    var encoders_ts_5, AssertionError, MIN_READ, MAX_SIZE, DenoBuffer;
    var __moduleName = context_54 && context_54.id;
    function assert(cond, msg = "Assertion failed.") {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }
    exports_54("assert", assert);
    function copy(src, dst, off = 0) {
        const r = dst.byteLength - off;
        if (src.byteLength > r) {
            src = src.subarray(0, r);
        }
        dst.set(src, off);
        return src.byteLength;
    }
    function concat(origin, b) {
        if (origin === undefined && b === undefined) {
            return new Uint8Array(0);
        }
        if (origin === undefined) {
            return b;
        }
        if (b === undefined) {
            return origin;
        }
        const output = new Uint8Array(origin.length + b.length);
        output.set(origin, 0);
        output.set(b, origin.length);
        return output;
    }
    exports_54("concat", concat);
    function append(origin, b) {
        return concat(origin, Uint8Array.of(b));
    }
    exports_54("append", append);
    function readAll(r) {
        const buf = new DenoBuffer();
        buf.readFrom(r);
        return buf.bytes();
    }
    exports_54("readAll", readAll);
    function writeAll(w, arr) {
        let nwritten = 0;
        while (nwritten < arr.length) {
            nwritten += w.write(arr.subarray(nwritten));
        }
    }
    exports_54("writeAll", writeAll);
    return {
        setters: [
            function (encoders_ts_5_1) {
                encoders_ts_5 = encoders_ts_5_1;
            }
        ],
        execute: function () {
            AssertionError = class AssertionError extends Error {
                constructor(msg) {
                    super(msg);
                    this.name = "AssertionError";
                }
            };
            exports_54("AssertionError", AssertionError);
            MIN_READ = 32 * 1024;
            exports_54("MAX_SIZE", MAX_SIZE = 2 ** 32 - 2);
            DenoBuffer = class DenoBuffer {
                constructor(ab) {
                    this._off = 0;
                    this._tryGrowByReslice = (n) => {
                        const l = this._buf.byteLength;
                        if (n <= this.capacity - l) {
                            this._reslice(l + n);
                            return l;
                        }
                        return -1;
                    };
                    this._reslice = (len) => {
                        assert(len <= this._buf.buffer.byteLength);
                        this._buf = new Uint8Array(this._buf.buffer, 0, len);
                    };
                    this._grow = (n) => {
                        const m = this.length;
                        if (m === 0 && this._off !== 0) {
                            this.reset();
                        }
                        const i = this._tryGrowByReslice(n);
                        if (i >= 0) {
                            return i;
                        }
                        const c = this.capacity;
                        if (n <= Math.floor(c / 2) - m) {
                            copy(this._buf.subarray(this._off), this._buf);
                        }
                        else if (c + n > MAX_SIZE) {
                            throw new Error("The buffer cannot be grown beyond the maximum size.");
                        }
                        else {
                            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE));
                            copy(this._buf.subarray(this._off), buf);
                            this._buf = buf;
                        }
                        this._off = 0;
                        this._reslice(Math.min(m + n, MAX_SIZE));
                        return m;
                    };
                    if (ab == null) {
                        this._buf = new Uint8Array(0);
                        return;
                    }
                    this._buf = new Uint8Array(ab);
                }
                bytes(options = { copy: true }) {
                    if (options.copy === false)
                        return this._buf.subarray(this._off);
                    return this._buf.slice(this._off);
                }
                empty() {
                    return this._buf.byteLength <= this._off;
                }
                get length() {
                    return this._buf.byteLength - this._off;
                }
                get capacity() {
                    return this._buf.buffer.byteLength;
                }
                truncate(n) {
                    if (n === 0) {
                        this.reset();
                        return;
                    }
                    if (n < 0 || n > this.length) {
                        throw Error("bytes.Buffer: truncation out of range");
                    }
                    this._reslice(this._off + n);
                }
                reset() {
                    this._reslice(0);
                    this._off = 0;
                }
                readByte() {
                    const a = new Uint8Array(1);
                    if (this.read(a)) {
                        return a[0];
                    }
                    return null;
                }
                read(p) {
                    if (this.empty()) {
                        this.reset();
                        if (p.byteLength === 0) {
                            return 0;
                        }
                        return null;
                    }
                    const nread = copy(this._buf.subarray(this._off), p);
                    this._off += nread;
                    return nread;
                }
                writeByte(n) {
                    return this.write(Uint8Array.of(n));
                }
                writeString(s) {
                    return this.write(encoders_ts_5.TE.encode(s));
                }
                write(p) {
                    const m = this._grow(p.byteLength);
                    return copy(p, this._buf, m);
                }
                grow(n) {
                    if (n < 0) {
                        throw Error("Buffer._grow: negative count");
                    }
                    const m = this._grow(n);
                    this._reslice(m);
                }
                readFrom(r) {
                    let n = 0;
                    const tmp = new Uint8Array(MIN_READ);
                    while (true) {
                        const shouldGrow = this.capacity - this.length < MIN_READ;
                        const buf = shouldGrow
                            ? tmp
                            : new Uint8Array(this._buf.buffer, this.length);
                        const nread = r.read(buf);
                        if (nread === null) {
                            return n;
                        }
                        if (shouldGrow)
                            this.write(buf.subarray(0, nread));
                        else
                            this._reslice(this.length + nread);
                        n += nread;
                    }
                }
            };
            exports_54("DenoBuffer", DenoBuffer);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/parser", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/denobuffer", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_55, context_55) {
    "use strict";
    var denobuffer_ts_1, encoders_ts_6, Kind, ASCII_0, ASCII_9, Parser, State, cc;
    var __moduleName = context_55 && context_55.id;
    function describe(e) {
        let ks;
        let data = "";
        switch (e.kind) {
            case Kind.MSG:
                ks = "MSG";
                break;
            case Kind.OK:
                ks = "OK";
                break;
            case Kind.ERR:
                ks = "ERR";
                data = encoders_ts_6.TD.decode(e.data);
                break;
            case Kind.PING:
                ks = "PING";
                break;
            case Kind.PONG:
                ks = "PONG";
                break;
            case Kind.INFO:
                ks = "INFO";
                data = encoders_ts_6.TD.decode(e.data);
        }
        return `${ks}: ${data}`;
    }
    exports_55("describe", describe);
    function newMsgArg() {
        const ma = {};
        ma.sid = -1;
        ma.hdr = -1;
        ma.size = -1;
        return ma;
    }
    return {
        setters: [
            function (denobuffer_ts_1_1) {
                denobuffer_ts_1 = denobuffer_ts_1_1;
            },
            function (encoders_ts_6_1) {
                encoders_ts_6 = encoders_ts_6_1;
            }
        ],
        execute: function () {
            (function (Kind) {
                Kind[Kind["OK"] = 0] = "OK";
                Kind[Kind["ERR"] = 1] = "ERR";
                Kind[Kind["MSG"] = 2] = "MSG";
                Kind[Kind["INFO"] = 3] = "INFO";
                Kind[Kind["PING"] = 4] = "PING";
                Kind[Kind["PONG"] = 5] = "PONG";
            })(Kind || (Kind = {}));
            exports_55("Kind", Kind);
            ASCII_0 = 48;
            ASCII_9 = 57;
            Parser = class Parser {
                constructor(dispatcher) {
                    this.state = State.OP_START;
                    this.as = 0;
                    this.drop = 0;
                    this.hdr = 0;
                    this.dispatcher = dispatcher;
                    this.state = State.OP_START;
                }
                parse(buf) {
                    if (typeof module !== "undefined" && module.exports) {
                        buf.subarray = buf.slice;
                    }
                    let i;
                    for (i = 0; i < buf.length; i++) {
                        const b = buf[i];
                        switch (this.state) {
                            case State.OP_START:
                                switch (b) {
                                    case cc.M:
                                    case cc.m:
                                        this.state = State.OP_M;
                                        this.hdr = -1;
                                        this.ma = newMsgArg();
                                        break;
                                    case cc.H:
                                    case cc.h:
                                        this.state = State.OP_H;
                                        this.hdr = 0;
                                        this.ma = newMsgArg();
                                        break;
                                    case cc.P:
                                    case cc.p:
                                        this.state = State.OP_P;
                                        break;
                                    case cc.PLUS:
                                        this.state = State.OP_PLUS;
                                        break;
                                    case cc.MINUS:
                                        this.state = State.OP_MINUS;
                                        break;
                                    case cc.I:
                                    case cc.i:
                                        this.state = State.OP_I;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_H:
                                switch (b) {
                                    case cc.M:
                                    case cc.m:
                                        this.state = State.OP_M;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_M:
                                switch (b) {
                                    case cc.S:
                                    case cc.s:
                                        this.state = State.OP_MS;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MS:
                                switch (b) {
                                    case cc.G:
                                    case cc.g:
                                        this.state = State.OP_MSG;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MSG:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        this.state = State.OP_MSG_SPC;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MSG_SPC:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        continue;
                                    default:
                                        this.state = State.MSG_ARG;
                                        this.as = i;
                                }
                                break;
                            case State.MSG_ARG:
                                switch (b) {
                                    case cc.CR:
                                        this.drop = 1;
                                        break;
                                    case cc.NL:
                                        const arg = this.argBuf
                                            ? this.argBuf.bytes()
                                            : buf.subarray(this.as, i - this.drop);
                                        this.processMsgArgs(arg);
                                        this.drop = 0;
                                        this.as = i + 1;
                                        this.state = State.MSG_PAYLOAD;
                                        i = this.as + this.ma.size - 1;
                                        break;
                                    default:
                                        if (this.argBuf) {
                                            this.argBuf.writeByte(b);
                                        }
                                }
                                break;
                            case State.MSG_PAYLOAD:
                                if (this.msgBuf) {
                                    if (this.msgBuf.length >= this.ma.size) {
                                        const data = this.msgBuf.bytes({ copy: false });
                                        this.dispatcher.push({ kind: Kind.MSG, msg: this.ma, data: data });
                                        this.argBuf = undefined;
                                        this.msgBuf = undefined;
                                        this.state = State.MSG_END;
                                    }
                                    else {
                                        let toCopy = this.ma.size - this.msgBuf.length;
                                        const avail = buf.length - i;
                                        if (avail < toCopy) {
                                            toCopy = avail;
                                        }
                                        if (toCopy > 0) {
                                            this.msgBuf.write(buf.subarray(i, i + toCopy));
                                            i = (i + toCopy) - 1;
                                        }
                                        else {
                                            this.msgBuf.writeByte(b);
                                        }
                                    }
                                }
                                else if (i - this.as >= this.ma.size) {
                                    this.dispatcher.push({ kind: Kind.MSG, msg: this.ma, data: buf.subarray(this.as, i) });
                                    this.argBuf = undefined;
                                    this.msgBuf = undefined;
                                    this.state = State.MSG_END;
                                }
                                break;
                            case State.MSG_END:
                                switch (b) {
                                    case cc.NL:
                                        this.drop = 0;
                                        this.as = i + 1;
                                        this.state = State.OP_START;
                                        break;
                                    default:
                                        continue;
                                }
                                break;
                            case State.OP_PLUS:
                                switch (b) {
                                    case cc.O:
                                    case cc.o:
                                        this.state = State.OP_PLUS_O;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PLUS_O:
                                switch (b) {
                                    case cc.K:
                                    case cc.k:
                                        this.state = State.OP_PLUS_OK;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PLUS_OK:
                                switch (b) {
                                    case cc.NL:
                                        this.dispatcher.push({ kind: Kind.OK });
                                        this.drop = 0;
                                        this.state = State.OP_START;
                                        break;
                                }
                                break;
                            case State.OP_MINUS:
                                switch (b) {
                                    case cc.E:
                                    case cc.e:
                                        this.state = State.OP_MINUS_E;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MINUS_E:
                                switch (b) {
                                    case cc.R:
                                    case cc.r:
                                        this.state = State.OP_MINUS_ER;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MINUS_ER:
                                switch (b) {
                                    case cc.R:
                                    case cc.r:
                                        this.state = State.OP_MINUS_ERR;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MINUS_ERR:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        this.state = State.OP_MINUS_ERR_SPC;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_MINUS_ERR_SPC:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        continue;
                                    default:
                                        this.state = State.MINUS_ERR_ARG;
                                        this.as = i;
                                }
                                break;
                            case State.MINUS_ERR_ARG:
                                switch (b) {
                                    case cc.CR:
                                        this.drop = 1;
                                        break;
                                    case cc.NL:
                                        let arg;
                                        if (this.argBuf) {
                                            arg = this.argBuf.bytes();
                                            this.argBuf = undefined;
                                        }
                                        else {
                                            arg = buf.subarray(this.as, i - this.drop);
                                        }
                                        this.dispatcher.push({ kind: Kind.ERR, data: arg });
                                        this.drop = 0;
                                        this.as = i + 1;
                                        this.state = State.OP_START;
                                        break;
                                    default:
                                        if (this.argBuf) {
                                            this.argBuf.write(Uint8Array.of(b));
                                        }
                                }
                                break;
                            case State.OP_P:
                                switch (b) {
                                    case cc.I:
                                    case cc.i:
                                        this.state = State.OP_PI;
                                        break;
                                    case cc.O:
                                    case cc.o:
                                        this.state = State.OP_PO;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PO:
                                switch (b) {
                                    case cc.N:
                                    case cc.n:
                                        this.state = State.OP_PON;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PON:
                                switch (b) {
                                    case cc.G:
                                    case cc.g:
                                        this.state = State.OP_PONG;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PONG:
                                switch (b) {
                                    case cc.NL:
                                        this.dispatcher.push({ kind: Kind.PONG });
                                        this.drop = 0;
                                        this.state = State.OP_START;
                                        break;
                                }
                                break;
                            case State.OP_PI:
                                switch (b) {
                                    case cc.N:
                                    case cc.n:
                                        this.state = State.OP_PIN;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PIN:
                                switch (b) {
                                    case cc.G:
                                    case cc.g:
                                        this.state = State.OP_PING;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_PING:
                                switch (b) {
                                    case cc.NL:
                                        this.dispatcher.push({ kind: Kind.PING });
                                        this.drop = 0;
                                        this.state = State.OP_START;
                                        break;
                                }
                                break;
                            case State.OP_I:
                                switch (b) {
                                    case cc.N:
                                    case cc.n:
                                        this.state = State.OP_IN;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_IN:
                                switch (b) {
                                    case cc.F:
                                    case cc.f:
                                        this.state = State.OP_INF;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_INF:
                                switch (b) {
                                    case cc.O:
                                    case cc.o:
                                        this.state = State.OP_INFO;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_INFO:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        this.state = State.OP_INFO_SPC;
                                        break;
                                    default:
                                        throw this.fail(buf.subarray(i));
                                }
                                break;
                            case State.OP_INFO_SPC:
                                switch (b) {
                                    case cc.SPACE:
                                    case cc.TAB:
                                        continue;
                                    default:
                                        this.state = State.INFO_ARG;
                                        this.as = i;
                                }
                                break;
                            case State.INFO_ARG:
                                switch (b) {
                                    case cc.CR:
                                        this.drop = 1;
                                        break;
                                    case cc.NL:
                                        let arg;
                                        if (this.argBuf) {
                                            arg = this.argBuf.bytes();
                                            this.argBuf = undefined;
                                        }
                                        else {
                                            arg = buf.subarray(this.as, i - this.drop);
                                        }
                                        this.dispatcher.push({ kind: Kind.INFO, data: arg });
                                        this.drop = 0;
                                        this.as = i + 1;
                                        this.state = State.OP_START;
                                        break;
                                    default:
                                        if (this.argBuf) {
                                            this.argBuf.writeByte(b);
                                        }
                                }
                                break;
                            default:
                                throw this.fail(buf.subarray(i));
                        }
                    }
                    if ((this.state === State.MSG_ARG || this.state === State.MINUS_ERR_ARG ||
                        this.state === State.INFO_ARG) && !this.argBuf) {
                        this.argBuf = new denobuffer_ts_1.DenoBuffer(buf.subarray(this.as, i - this.drop));
                    }
                    if (this.state === State.MSG_PAYLOAD && !this.msgBuf) {
                        if (!this.argBuf) {
                            this.cloneMsgArg();
                        }
                        this.msgBuf = new denobuffer_ts_1.DenoBuffer(buf.subarray(this.as));
                    }
                }
                cloneMsgArg() {
                    const s = this.ma.subject.length;
                    const r = this.ma.reply ? this.ma.reply.length : 0;
                    const buf = new Uint8Array(s + r);
                    buf.set(this.ma.subject);
                    if (this.ma.reply) {
                        buf.set(this.ma.reply, s);
                    }
                    this.argBuf = new denobuffer_ts_1.DenoBuffer(buf);
                    this.ma.subject = buf.subarray(0, s);
                    if (this.ma.reply) {
                        this.ma.reply = buf.subarray(r);
                    }
                }
                processMsgArgs(arg) {
                    if (this.hdr >= 0) {
                        return this.processHeaderMsgArgs(arg);
                    }
                    const args = [];
                    let start = -1;
                    for (let i = 0; i < arg.length; i++) {
                        const b = arg[i];
                        switch (b) {
                            case cc.SPACE:
                            case cc.TAB:
                            case cc.CR:
                            case cc.NL:
                                if (start >= 0) {
                                    args.push(arg.subarray(start, i));
                                    start = -1;
                                }
                                break;
                            default:
                                if (start < 0) {
                                    start = i;
                                }
                        }
                    }
                    if (start >= 0) {
                        args.push(arg.subarray(start));
                    }
                    switch (args.length) {
                        case 3:
                            this.ma.subject = args[0];
                            this.ma.sid = this.protoParseInt(args[1]);
                            this.ma.reply = undefined;
                            this.ma.size = this.protoParseInt(args[2]);
                            break;
                        case 4:
                            this.ma.subject = args[0];
                            this.ma.sid = this.protoParseInt(args[1]);
                            this.ma.reply = args[2];
                            this.ma.size = this.protoParseInt(args[3]);
                            break;
                        default:
                            throw this.fail(arg, "processMsgArgs Parse Error");
                    }
                    if (this.ma.sid < 0) {
                        throw this.fail(arg, "processMsgArgs Bad or Missing Sid Error");
                    }
                    if (this.ma.size < 0) {
                        throw this.fail(arg, "processMsgArgs Bad or Missing Size Error");
                    }
                }
                fail(data, label = "") {
                    if (!label) {
                        label = `parse error [${this.state}]`;
                    }
                    else {
                        label = `${label} [${this.state}]`;
                    }
                    return new Error(`${label}: ${encoders_ts_6.TD.decode(data)}`);
                }
                processHeaderMsgArgs(arg) {
                    const args = [];
                    let start = -1;
                    for (let i = 0; i < arg.length; i++) {
                        const b = arg[i];
                        switch (b) {
                            case cc.SPACE:
                            case cc.TAB:
                            case cc.CR:
                            case cc.NL:
                                if (start >= 0) {
                                    args.push(arg.subarray(start, i));
                                    start = -1;
                                }
                                break;
                            default:
                                if (start < 0) {
                                    start = i;
                                }
                        }
                    }
                    if (start >= 0) {
                        args.push(arg.subarray(start));
                    }
                    switch (args.length) {
                        case 4:
                            this.ma.subject = args[0];
                            this.ma.sid = this.protoParseInt(args[1]);
                            this.ma.reply = undefined;
                            this.ma.hdr = this.protoParseInt(args[2]);
                            this.ma.size = this.protoParseInt(args[3]);
                            break;
                        case 5:
                            this.ma.subject = args[0];
                            this.ma.sid = this.protoParseInt(args[1]);
                            this.ma.reply = args[2];
                            this.ma.hdr = this.protoParseInt(args[3]);
                            this.ma.size = this.protoParseInt(args[4]);
                            break;
                        default:
                            throw this.fail(arg, "processHeaderMsgArgs Parse Error");
                    }
                    if (this.ma.sid < 0) {
                        throw this.fail(arg, "processHeaderMsgArgs Bad or Missing Sid Error");
                    }
                    if (this.ma.hdr < 0 || this.ma.hdr > this.ma.size) {
                        throw this.fail(arg, "processHeaderMsgArgs Bad or Missing Header Size Error");
                    }
                    if (this.ma.size < 0) {
                        throw this.fail(arg, "processHeaderMsgArgs Bad or Missing Size Error");
                    }
                }
                protoParseInt(a) {
                    if (a.length === 0) {
                        return -1;
                    }
                    let n = 0;
                    for (let i = 0; i < a.length; i++) {
                        if (a[i] < ASCII_0 || a[i] > ASCII_9) {
                            return -1;
                        }
                        n = n * 10 + (a[i] - ASCII_0);
                    }
                    return n;
                }
            };
            exports_55("Parser", Parser);
            (function (State) {
                State[State["OP_START"] = 0] = "OP_START";
                State[State["OP_PLUS"] = 1] = "OP_PLUS";
                State[State["OP_PLUS_O"] = 2] = "OP_PLUS_O";
                State[State["OP_PLUS_OK"] = 3] = "OP_PLUS_OK";
                State[State["OP_MINUS"] = 4] = "OP_MINUS";
                State[State["OP_MINUS_E"] = 5] = "OP_MINUS_E";
                State[State["OP_MINUS_ER"] = 6] = "OP_MINUS_ER";
                State[State["OP_MINUS_ERR"] = 7] = "OP_MINUS_ERR";
                State[State["OP_MINUS_ERR_SPC"] = 8] = "OP_MINUS_ERR_SPC";
                State[State["MINUS_ERR_ARG"] = 9] = "MINUS_ERR_ARG";
                State[State["OP_M"] = 10] = "OP_M";
                State[State["OP_MS"] = 11] = "OP_MS";
                State[State["OP_MSG"] = 12] = "OP_MSG";
                State[State["OP_MSG_SPC"] = 13] = "OP_MSG_SPC";
                State[State["MSG_ARG"] = 14] = "MSG_ARG";
                State[State["MSG_PAYLOAD"] = 15] = "MSG_PAYLOAD";
                State[State["MSG_END"] = 16] = "MSG_END";
                State[State["OP_H"] = 17] = "OP_H";
                State[State["OP_P"] = 18] = "OP_P";
                State[State["OP_PI"] = 19] = "OP_PI";
                State[State["OP_PIN"] = 20] = "OP_PIN";
                State[State["OP_PING"] = 21] = "OP_PING";
                State[State["OP_PO"] = 22] = "OP_PO";
                State[State["OP_PON"] = 23] = "OP_PON";
                State[State["OP_PONG"] = 24] = "OP_PONG";
                State[State["OP_I"] = 25] = "OP_I";
                State[State["OP_IN"] = 26] = "OP_IN";
                State[State["OP_INF"] = 27] = "OP_INF";
                State[State["OP_INFO"] = 28] = "OP_INFO";
                State[State["OP_INFO_SPC"] = 29] = "OP_INFO_SPC";
                State[State["INFO_ARG"] = 30] = "INFO_ARG";
            })(State || (State = {}));
            exports_55("State", State);
            (function (cc) {
                cc[cc["CR"] = "\r".charCodeAt(0)] = "CR";
                cc[cc["E"] = "E".charCodeAt(0)] = "E";
                cc[cc["e"] = "e".charCodeAt(0)] = "e";
                cc[cc["F"] = "F".charCodeAt(0)] = "F";
                cc[cc["f"] = "f".charCodeAt(0)] = "f";
                cc[cc["G"] = "G".charCodeAt(0)] = "G";
                cc[cc["g"] = "g".charCodeAt(0)] = "g";
                cc[cc["H"] = "H".charCodeAt(0)] = "H";
                cc[cc["h"] = "h".charCodeAt(0)] = "h";
                cc[cc["I"] = "I".charCodeAt(0)] = "I";
                cc[cc["i"] = "i".charCodeAt(0)] = "i";
                cc[cc["K"] = "K".charCodeAt(0)] = "K";
                cc[cc["k"] = "k".charCodeAt(0)] = "k";
                cc[cc["M"] = "M".charCodeAt(0)] = "M";
                cc[cc["m"] = "m".charCodeAt(0)] = "m";
                cc[cc["MINUS"] = "-".charCodeAt(0)] = "MINUS";
                cc[cc["N"] = "N".charCodeAt(0)] = "N";
                cc[cc["n"] = "n".charCodeAt(0)] = "n";
                cc[cc["NL"] = "\n".charCodeAt(0)] = "NL";
                cc[cc["O"] = "O".charCodeAt(0)] = "O";
                cc[cc["o"] = "o".charCodeAt(0)] = "o";
                cc[cc["P"] = "P".charCodeAt(0)] = "P";
                cc[cc["p"] = "p".charCodeAt(0)] = "p";
                cc[cc["PLUS"] = "+".charCodeAt(0)] = "PLUS";
                cc[cc["R"] = "R".charCodeAt(0)] = "R";
                cc[cc["r"] = "r".charCodeAt(0)] = "r";
                cc[cc["S"] = "S".charCodeAt(0)] = "S";
                cc[cc["s"] = "s".charCodeAt(0)] = "s";
                cc[cc["SPACE"] = " ".charCodeAt(0)] = "SPACE";
                cc[cc["TAB"] = "\t".charCodeAt(0)] = "TAB";
            })(cc || (cc = {}));
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/msg", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/headers", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_56, context_56) {
    "use strict";
    var types_ts_4, headers_ts_1, encoders_ts_7, MsgImpl;
    var __moduleName = context_56 && context_56.id;
    return {
        setters: [
            function (types_ts_4_1) {
                types_ts_4 = types_ts_4_1;
            },
            function (headers_ts_1_1) {
                headers_ts_1 = headers_ts_1_1;
            },
            function (encoders_ts_7_1) {
                encoders_ts_7 = encoders_ts_7_1;
            }
        ],
        execute: function () {
            MsgImpl = class MsgImpl {
                constructor(msg, data, publisher) {
                    this._msg = msg;
                    this._rdata = data;
                    this.publisher = publisher;
                }
                get subject() {
                    if (this._subject) {
                        return this._subject;
                    }
                    this._subject = encoders_ts_7.TD.decode(this._msg.subject);
                    return this._subject;
                }
                get reply() {
                    if (this._reply) {
                        return this._reply;
                    }
                    this._reply = encoders_ts_7.TD.decode(this._msg.reply);
                    return this._reply;
                }
                get sid() {
                    return this._msg.sid;
                }
                get headers() {
                    if (this._msg.hdr > -1 && !this._headers) {
                        const buf = this._rdata.subarray(0, this._msg.hdr);
                        this._headers = headers_ts_1.MsgHdrsImpl.decode(buf);
                    }
                    return this._headers;
                }
                get data() {
                    if (!this._rdata) {
                        return new Uint8Array(0);
                    }
                    return this._msg.hdr > -1
                        ? this._rdata.subarray(this._msg.hdr)
                        : this._rdata;
                }
                respond(data = types_ts_4.Empty, opts) {
                    if (this.reply) {
                        this.publisher.publish(this.reply, data, opts);
                        return true;
                    }
                    return false;
                }
            };
            exports_56("MsgImpl", MsgImpl);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/protocol", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/transport", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nuid", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/databuffer", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/servers", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/queued_iterator", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscription", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscriptions", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/muxsubscription", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/heartbeats", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/parser", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/msg", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_57, context_57) {
    "use strict";
    var types_ts_5, transport_ts_1, error_ts_7, util_ts_7, nuid_ts_2, databuffer_ts_2, servers_ts_1, queued_iterator_ts_2, subscription_ts_1, subscriptions_ts_1, muxsubscription_ts_1, heartbeats_ts_1, parser_ts_1, msg_ts_1, encoders_ts_8, FLUSH_THRESHOLD, INFO, PONG_CMD, PING_CMD, Connect, ProtocolHandler;
    var __moduleName = context_57 && context_57.id;
    function createInbox() {
        return `_INBOX.${nuid_ts_2.nuid.next()}`;
    }
    exports_57("createInbox", createInbox);
    return {
        setters: [
            function (types_ts_5_1) {
                types_ts_5 = types_ts_5_1;
            },
            function (transport_ts_1_1) {
                transport_ts_1 = transport_ts_1_1;
            },
            function (error_ts_7_1) {
                error_ts_7 = error_ts_7_1;
            },
            function (util_ts_7_1) {
                util_ts_7 = util_ts_7_1;
            },
            function (nuid_ts_2_1) {
                nuid_ts_2 = nuid_ts_2_1;
            },
            function (databuffer_ts_2_1) {
                databuffer_ts_2 = databuffer_ts_2_1;
            },
            function (servers_ts_1_1) {
                servers_ts_1 = servers_ts_1_1;
            },
            function (queued_iterator_ts_2_1) {
                queued_iterator_ts_2 = queued_iterator_ts_2_1;
            },
            function (subscription_ts_1_1) {
                subscription_ts_1 = subscription_ts_1_1;
            },
            function (subscriptions_ts_1_1) {
                subscriptions_ts_1 = subscriptions_ts_1_1;
            },
            function (muxsubscription_ts_1_1) {
                muxsubscription_ts_1 = muxsubscription_ts_1_1;
            },
            function (heartbeats_ts_1_1) {
                heartbeats_ts_1 = heartbeats_ts_1_1;
            },
            function (parser_ts_1_1) {
                parser_ts_1 = parser_ts_1_1;
            },
            function (msg_ts_1_1) {
                msg_ts_1 = msg_ts_1_1;
            },
            function (encoders_ts_8_1) {
                encoders_ts_8 = encoders_ts_8_1;
            }
        ],
        execute: function () {
            FLUSH_THRESHOLD = 1024 * 32;
            exports_57("INFO", INFO = /^INFO\s+([^\r\n]+)\r\n/i);
            PONG_CMD = encoders_ts_8.fastEncoder("PONG\r\n");
            PING_CMD = encoders_ts_8.fastEncoder("PING\r\n");
            Connect = class Connect {
                constructor(transport, opts, nonce) {
                    this.protocol = 1;
                    if (opts.noEcho) {
                        this.echo = false;
                    }
                    if (opts.noResponders) {
                        this.no_responders = true;
                    }
                    const creds = (opts && opts.authenticator ? opts.authenticator(nonce) : {}) || {};
                    util_ts_7.extend(this, opts, transport, creds);
                }
            };
            exports_57("Connect", Connect);
            ProtocolHandler = class ProtocolHandler {
                constructor(options, publisher) {
                    this.connected = false;
                    this.connectedOnce = false;
                    this.infoReceived = false;
                    this.pout = 0;
                    this.noMorePublishing = false;
                    this._closed = false;
                    this.listeners = [];
                    this.outMsgs = 0;
                    this.inMsgs = 0;
                    this.outBytes = 0;
                    this.inBytes = 0;
                    this.pendingLimit = FLUSH_THRESHOLD;
                    this.options = options;
                    this.publisher = publisher;
                    this.subscriptions = new subscriptions_ts_1.Subscriptions();
                    this.muxSubscriptions = new muxsubscription_ts_1.MuxSubscription();
                    this.outbound = new databuffer_ts_2.DataBuffer();
                    this.pongs = [];
                    this.pendingLimit = options.pendingLimit || this.pendingLimit;
                    this.servers = new servers_ts_1.Servers(!options.noRandomize, options.servers);
                    this.closed = util_ts_7.deferred();
                    this.parser = new parser_ts_1.Parser(this);
                    this.heartbeats = new heartbeats_ts_1.Heartbeat(this, this.options.pingInterval || types_ts_5.DEFAULT_PING_INTERVAL, this.options.maxPingOut || types_ts_5.DEFAULT_MAX_PING_OUT);
                }
                resetOutbound() {
                    this.outbound.reset();
                    const pongs = this.pongs;
                    this.pongs = [];
                    pongs.forEach((p) => {
                        p.reject(error_ts_7.NatsError.errorForCode(error_ts_7.ErrorCode.DISCONNECT));
                    });
                    this.parser = new parser_ts_1.Parser(this);
                    this.infoReceived = false;
                }
                dispatchStatus(status) {
                    this.listeners.forEach((q) => {
                        q.push(status);
                    });
                }
                status() {
                    const iter = new queued_iterator_ts_2.QueuedIterator();
                    this.listeners.push(iter);
                    return iter;
                }
                prepare() {
                    this.info = undefined;
                    this.resetOutbound();
                    const pong = util_ts_7.deferred();
                    this.pongs.unshift(pong);
                    this.connectError = undefined;
                    this.connectError = (err) => {
                        pong.reject(err);
                    };
                    this.transport = transport_ts_1.newTransport();
                    this.transport.closed()
                        .then(async (err) => {
                        this.connected = false;
                        if (!this.isClosed()) {
                            await this.disconnected(this.transport.closeError);
                            return;
                        }
                    });
                    return pong;
                }
                disconnect() {
                    this.dispatchStatus({ type: types_ts_5.DebugEvents.STALE_CONNECTION, data: "" });
                    this.transport.disconnect();
                }
                async disconnected(err) {
                    this.dispatchStatus({
                        type: types_ts_5.Events.DISCONNECT,
                        data: this.servers.getCurrentServer().toString(),
                    });
                    if (this.options.reconnect) {
                        await this.dialLoop()
                            .then(() => {
                            this.dispatchStatus({
                                type: types_ts_5.Events.RECONNECT,
                                data: this.servers.getCurrentServer().toString(),
                            });
                        })
                            .catch((err) => {
                            this._close(err);
                        });
                    }
                    else {
                        await this._close();
                    }
                }
                async dial(srv) {
                    const pong = this.prepare();
                    const timer = util_ts_7.timeout(this.options.timeout || 20000);
                    try {
                        await this.transport.connect(srv.hostport(), this.options);
                        (async () => {
                            try {
                                for await (const b of this.transport) {
                                    this.parser.parse(b);
                                }
                            }
                            catch (err) {
                                console.log("reader closed", err);
                            }
                        })().then();
                    }
                    catch (err) {
                        pong.reject(err);
                    }
                    try {
                        await Promise.race([timer, pong]);
                        timer.cancel();
                        this.connected = true;
                        this.connectError = undefined;
                        this.sendSubscriptions();
                        this.connectedOnce = true;
                        this.server.didConnect = true;
                        this.server.reconnects = 0;
                        this.infoReceived = true;
                        this.flushPending();
                        this.heartbeats.start();
                    }
                    catch (err) {
                        timer.cancel();
                        await this.transport.close(err);
                        throw err;
                    }
                }
                async dialLoop() {
                    let lastError;
                    while (true) {
                        let wait = this.options.reconnectDelayHandler
                            ? this.options.reconnectDelayHandler()
                            : types_ts_5.DEFAULT_RECONNECT_TIME_WAIT;
                        let maxWait = wait;
                        const srv = this.selectServer();
                        if (!srv) {
                            throw lastError || error_ts_7.NatsError.errorForCode(error_ts_7.ErrorCode.CONNECTION_REFUSED);
                        }
                        const now = Date.now();
                        if (srv.lastConnect === 0 || srv.lastConnect + wait <= now) {
                            srv.lastConnect = Date.now();
                            try {
                                this.dispatchStatus({ type: types_ts_5.DebugEvents.RECONNECTING, data: srv.toString() });
                                await this.dial(srv);
                                break;
                            }
                            catch (err) {
                                lastError = err;
                                if (!this.connectedOnce) {
                                    if (!this.options.waitOnFirstConnect) {
                                        this.servers.removeCurrentServer();
                                    }
                                    continue;
                                }
                                srv.reconnects++;
                                const mra = this.options.maxReconnectAttempts || 0;
                                if (mra !== -1 && srv.reconnects >= mra) {
                                    this.servers.removeCurrentServer();
                                }
                            }
                        }
                        else {
                            maxWait = Math.min(maxWait, srv.lastConnect + wait - now);
                            await util_ts_7.delay(maxWait);
                        }
                    }
                }
                static async connect(options, publisher) {
                    const h = new ProtocolHandler(options, publisher);
                    await h.dialLoop();
                    return h;
                }
                static toError(s) {
                    let t = s ? s.toLowerCase() : "";
                    if (t.indexOf("permissions violation") !== -1) {
                        return new error_ts_7.NatsError(s, error_ts_7.ErrorCode.PERMISSIONS_VIOLATION);
                    }
                    else if (t.indexOf("authorization violation") !== -1) {
                        return new error_ts_7.NatsError(s, error_ts_7.ErrorCode.AUTHORIZATION_VIOLATION);
                    }
                    else {
                        return new error_ts_7.NatsError(s, error_ts_7.ErrorCode.NATS_PROTOCOL_ERR);
                    }
                }
                processMsg(msg, data) {
                    this.inMsgs++;
                    this.inBytes += data.length;
                    if (!this.subscriptions.sidCounter) {
                        return;
                    }
                    let sub = this.subscriptions.get(msg.sid);
                    if (!sub) {
                        return;
                    }
                    sub.received += 1;
                    if (sub.callback) {
                        sub.callback(null, new msg_ts_1.MsgImpl(msg, data, this));
                    }
                    if (sub.max !== undefined && sub.received >= sub.max) {
                        sub.unsubscribe();
                    }
                }
                async processError(m) {
                    const s = encoders_ts_8.fastDecoder(m);
                    const err = ProtocolHandler.toError(s);
                    this.subscriptions.handleError(err);
                    await this._close(err);
                }
                processPing() {
                    this.transport.send(PONG_CMD);
                }
                processPong() {
                    this.pout = 0;
                    const cb = this.pongs.shift();
                    if (cb) {
                        cb.resolve();
                    }
                }
                processInfo(m) {
                    this.info = JSON.parse(encoders_ts_8.fastDecoder(m));
                    const updates = this.servers.update(this.info);
                    if (!this.infoReceived) {
                        const { version, lang } = this.transport;
                        try {
                            const c = new Connect({ version, lang }, this.options, this.info.nonce);
                            const cs = JSON.stringify(c);
                            this.transport.send(encoders_ts_8.fastEncoder(`CONNECT ${cs}${util_ts_7.CR_LF}`));
                            this.transport.send(PING_CMD);
                        }
                        catch (err) {
                            this._close(error_ts_7.NatsError.errorForCode(error_ts_7.ErrorCode.BAD_AUTHENTICATION, err));
                        }
                    }
                    if (updates) {
                        this.dispatchStatus({ type: types_ts_5.Events.UPDATE, data: updates });
                    }
                    const ldm = this.info.ldm !== undefined ? this.info.ldm : false;
                    if (ldm) {
                        this.dispatchStatus({
                            type: types_ts_5.Events.LDM,
                            data: this.servers.getCurrentServer().toString(),
                        });
                    }
                }
                push(e) {
                    switch (e.kind) {
                        case parser_ts_1.Kind.MSG:
                            const { msg, data } = e;
                            this.processMsg(msg, data);
                            break;
                        case parser_ts_1.Kind.OK:
                            break;
                        case parser_ts_1.Kind.ERR:
                            this.processError(e.data);
                            break;
                        case parser_ts_1.Kind.PING:
                            this.processPing();
                            break;
                        case parser_ts_1.Kind.PONG:
                            this.processPong();
                            break;
                        case parser_ts_1.Kind.INFO:
                            this.processInfo(e.data);
                            break;
                    }
                }
                sendCommand(cmd, ...payloads) {
                    const len = this.outbound.length();
                    let buf;
                    if (typeof cmd === "string") {
                        buf = encoders_ts_8.fastEncoder(cmd);
                    }
                    else {
                        buf = cmd;
                    }
                    this.outbound.fill(buf, ...payloads);
                    if (len === 0) {
                        setTimeout(() => {
                            this.flushPending();
                        });
                    }
                    else if (this.outbound.size() >= this.pendingLimit) {
                        this.flushPending();
                    }
                }
                publish(subject, data, options) {
                    if (this.isClosed()) {
                        throw error_ts_7.NatsError.errorForCode(error_ts_7.ErrorCode.CONNECTION_CLOSED);
                    }
                    if (this.noMorePublishing) {
                        throw error_ts_7.NatsError.errorForCode(error_ts_7.ErrorCode.CONNECTION_DRAINING);
                    }
                    let len = data.length;
                    options = options || {};
                    options.reply = options.reply || "";
                    let headers = types_ts_5.Empty;
                    let hlen = 0;
                    if (options.headers) {
                        if (!this.options.headers) {
                            throw new error_ts_7.NatsError("headers", error_ts_7.ErrorCode.SERVER_OPTION_NA);
                        }
                        const hdrs = options.headers;
                        headers = hdrs.encode();
                        hlen = headers.length;
                        len = data.length + hlen;
                    }
                    if (len > this.info.max_payload) {
                        throw error_ts_7.NatsError.errorForCode((error_ts_7.ErrorCode.MAX_PAYLOAD_EXCEEDED));
                    }
                    this.outBytes += len;
                    this.outMsgs++;
                    let proto;
                    if (options.headers) {
                        if (options.reply) {
                            proto = `HPUB ${subject} ${options.reply} ${hlen} ${len}${util_ts_7.CR_LF}`;
                        }
                        else {
                            proto = `HPUB ${subject} ${hlen} ${len}\r\n`;
                        }
                        this.sendCommand(proto, headers, data, util_ts_7.CRLF);
                    }
                    else {
                        if (options.reply) {
                            proto = `PUB ${subject} ${options.reply} ${len}\r\n`;
                        }
                        else {
                            proto = `PUB ${subject} ${len}\r\n`;
                        }
                        this.sendCommand(proto, data, util_ts_7.CRLF);
                    }
                }
                request(r) {
                    this.initMux();
                    this.muxSubscriptions.add(r);
                    return r;
                }
                subscribe(s) {
                    this.subscriptions.add(s);
                    if (s.queue) {
                        this.sendCommand(`SUB ${s.subject} ${s.queue} ${s.sid}\r\n`);
                    }
                    else {
                        this.sendCommand(`SUB ${s.subject} ${s.sid}\r\n`);
                    }
                    if (s.max) {
                        this.unsubscribe(s, s.max);
                    }
                    return s;
                }
                unsubscribe(s, max) {
                    this.unsub(s, max);
                    if (s.max === undefined || s.received >= s.max) {
                        this.subscriptions.cancel(s);
                    }
                }
                unsub(s, max) {
                    if (!s || this.isClosed()) {
                        return;
                    }
                    if (max) {
                        this.sendCommand(`UNSUB ${s.sid} ${max}${util_ts_7.CR_LF}`);
                    }
                    else {
                        this.sendCommand(`UNSUB ${s.sid}${util_ts_7.CR_LF}`);
                    }
                    s.max = max;
                }
                flush(p) {
                    if (!p) {
                        p = util_ts_7.deferred();
                    }
                    this.pongs.push(p);
                    this.sendCommand(PING_CMD);
                    return p;
                }
                sendSubscriptions() {
                    let cmds = [];
                    this.subscriptions.all().forEach((s) => {
                        const sub = s;
                        if (sub.queue) {
                            cmds.push(`SUB ${sub.subject} ${sub.queue} ${sub.sid}${util_ts_7.CR_LF}`);
                        }
                        else {
                            cmds.push(`SUB ${sub.subject} ${sub.sid}${util_ts_7.CR_LF}`);
                        }
                    });
                    if (cmds.length) {
                        this.transport.send(encoders_ts_8.fastEncoder(cmds.join("")));
                    }
                }
                async _close(err) {
                    if (this._closed) {
                        return;
                    }
                    this.heartbeats.cancel();
                    if (this.connectError) {
                        this.connectError(err);
                        this.connectError = undefined;
                    }
                    this.muxSubscriptions.close();
                    this.subscriptions.close();
                    this.listeners.forEach((l) => {
                        l.stop();
                    });
                    this._closed = true;
                    await this.transport.close(err);
                    await this.closed.resolve(err);
                }
                close() {
                    return this._close();
                }
                isClosed() {
                    return this._closed;
                }
                drain() {
                    let subs = this.subscriptions.all();
                    let promises = [];
                    subs.forEach((sub) => {
                        promises.push(sub.drain());
                    });
                    return Promise.all(promises)
                        .then(async () => {
                        this.noMorePublishing = true;
                        return this.close();
                    })
                        .catch(() => {
                    });
                }
                flushPending() {
                    if (!this.infoReceived || !this.connected) {
                        return;
                    }
                    if (this.outbound.size()) {
                        let d = this.outbound.drain();
                        this.transport.send(d);
                    }
                }
                initMux() {
                    let mux = this.subscriptions.getMux();
                    if (!mux) {
                        let inbox = this.muxSubscriptions.init();
                        const sub = new subscription_ts_1.SubscriptionImpl(this, `${inbox}*`);
                        sub.callback = this.muxSubscriptions.dispatcher();
                        this.subscriptions.setMux(sub);
                        this.subscribe(sub);
                    }
                }
                selectServer() {
                    let server = this.servers.selectServer();
                    if (server === undefined) {
                        return undefined;
                    }
                    this.server = server;
                    return this.server;
                }
                getServer() {
                    return this.server;
                }
            };
            exports_57("ProtocolHandler", ProtocolHandler);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/options", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/authenticator"], function (exports_58, context_58) {
    "use strict";
    var util_ts_8, error_ts_8, types_ts_6, authenticator_ts_1;
    var __moduleName = context_58 && context_58.id;
    function defaultOptions() {
        return {
            maxPingOut: types_ts_6.DEFAULT_MAX_PING_OUT,
            maxReconnectAttempts: types_ts_6.DEFAULT_MAX_RECONNECT_ATTEMPTS,
            noRandomize: false,
            pedantic: false,
            pingInterval: types_ts_6.DEFAULT_PING_INTERVAL,
            reconnect: true,
            reconnectJitter: types_ts_6.DEFAULT_JITTER,
            reconnectJitterTLS: types_ts_6.DEFAULT_JITTER_TLS,
            reconnectTimeWait: types_ts_6.DEFAULT_RECONNECT_TIME_WAIT,
            tls: undefined,
            verbose: false,
            waitOnFirstConnect: false,
        };
    }
    exports_58("defaultOptions", defaultOptions);
    function parseOptions(opts) {
        opts = opts || { servers: [types_ts_6.DEFAULT_HOSTPORT] };
        if (opts.port) {
            opts.servers = [`${types_ts_6.DEFAULT_HOST}:${opts.port}`];
        }
        if (typeof opts.servers === "string") {
            opts.servers = [opts.servers];
        }
        if (opts.servers && opts.servers.length === 0) {
            opts.servers = [types_ts_6.DEFAULT_HOSTPORT];
        }
        const options = util_ts_8.extend(defaultOptions(), opts);
        if (opts.user && opts.token) {
            throw error_ts_8.NatsError.errorForCode(error_ts_8.ErrorCode.BAD_AUTHENTICATION);
        }
        if (opts.authenticator && (opts.token || opts.user || opts.pass)) {
            throw error_ts_8.NatsError.errorForCode(error_ts_8.ErrorCode.BAD_AUTHENTICATION);
        }
        options.authenticator = authenticator_ts_1.buildAuthenticator(options);
        ["reconnectDelayHandler", "authenticator"].forEach((n) => {
            if (options[n] && typeof options[n] !== "function") {
                throw new error_ts_8.NatsError(`${n} option should be a function`, error_ts_8.ErrorCode.NOT_FUNC);
            }
        });
        if (!options.reconnectDelayHandler) {
            options.reconnectDelayHandler = () => {
                let extra = options.tls
                    ? options.reconnectJitterTLS
                    : options.reconnectJitter;
                if (extra) {
                    extra++;
                    extra = Math.floor(Math.random() * extra);
                }
                return options.reconnectTimeWait + extra;
            };
        }
        return options;
    }
    exports_58("parseOptions", parseOptions);
    function checkOptions(info, options) {
        const { proto, headers, tls_required } = info;
        if ((proto === undefined || proto < 1) && options.noEcho) {
            throw new error_ts_8.NatsError("noEcho", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
        if ((proto === undefined || proto < 1) && options.headers) {
            throw new error_ts_8.NatsError("headers", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
        if (options.headers && headers !== true) {
            throw new error_ts_8.NatsError("headers", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
        if ((proto === undefined || proto < 1) && options.noResponders) {
            throw new error_ts_8.NatsError("noResponders", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
        if ((!headers) && options.noResponders) {
            throw new error_ts_8.NatsError("noResponders - requires headers", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
        if (options.tls && !tls_required) {
            throw new error_ts_8.NatsError("tls", error_ts_8.ErrorCode.SERVER_OPTION_NA);
        }
    }
    exports_58("checkOptions", checkOptions);
    return {
        setters: [
            function (util_ts_8_1) {
                util_ts_8 = util_ts_8_1;
            },
            function (error_ts_8_1) {
                error_ts_8 = error_ts_8_1;
            },
            function (types_ts_6_1) {
                types_ts_6 = types_ts_6_1;
            },
            function (authenticator_ts_1_1) {
                authenticator_ts_1 = authenticator_ts_1_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nats", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/protocol", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscription", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/options", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/queued_iterator", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/request"], function (exports_59, context_59) {
    "use strict";
    var util_ts_9, protocol_ts_2, subscription_ts_2, error_ts_9, types_ts_7, options_ts_1, queued_iterator_ts_3, request_ts_1, NatsConnectionImpl;
    var __moduleName = context_59 && context_59.id;
    return {
        setters: [
            function (util_ts_9_1) {
                util_ts_9 = util_ts_9_1;
            },
            function (protocol_ts_2_1) {
                protocol_ts_2 = protocol_ts_2_1;
            },
            function (subscription_ts_2_1) {
                subscription_ts_2 = subscription_ts_2_1;
            },
            function (error_ts_9_1) {
                error_ts_9 = error_ts_9_1;
            },
            function (types_ts_7_1) {
                types_ts_7 = types_ts_7_1;
            },
            function (options_ts_1_1) {
                options_ts_1 = options_ts_1_1;
            },
            function (queued_iterator_ts_3_1) {
                queued_iterator_ts_3 = queued_iterator_ts_3_1;
            },
            function (request_ts_1_1) {
                request_ts_1 = request_ts_1_1;
            }
        ],
        execute: function () {
            NatsConnectionImpl = class NatsConnectionImpl {
                constructor(opts) {
                    this.draining = false;
                    this.listeners = [];
                    this.options = options_ts_1.parseOptions(opts);
                }
                static connect(opts = {}) {
                    return new Promise((resolve, reject) => {
                        let nc = new NatsConnectionImpl(opts);
                        protocol_ts_2.ProtocolHandler.connect(nc.options, nc)
                            .then((ph) => {
                            nc.protocol = ph;
                            (async function () {
                                for await (const s of ph.status()) {
                                    nc.listeners.forEach((l) => {
                                        l.push(s);
                                    });
                                }
                            })();
                            resolve(nc);
                        })
                            .catch((err) => {
                            reject(err);
                        });
                    });
                }
                closed() {
                    return this.protocol.closed;
                }
                async close() {
                    await this.protocol.close();
                }
                publish(subject, data = types_ts_7.Empty, options) {
                    subject = subject || "";
                    if (subject.length === 0) {
                        throw error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.BAD_SUBJECT);
                    }
                    if (data && !util_ts_9.isUint8Array(data)) {
                        throw error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.BAD_PAYLOAD);
                    }
                    this.protocol.publish(subject, data, options);
                }
                subscribe(subject, opts = {}) {
                    if (this.isClosed()) {
                        throw error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_CLOSED);
                    }
                    if (this.isDraining()) {
                        throw error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_DRAINING);
                    }
                    subject = subject || "";
                    if (subject.length === 0) {
                        throw error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.BAD_SUBJECT);
                    }
                    const sub = new subscription_ts_2.SubscriptionImpl(this.protocol, subject, opts);
                    this.protocol.subscribe(sub);
                    return sub;
                }
                request(subject, data = types_ts_7.Empty, opts = { timeout: 1000, noMux: false }) {
                    if (this.isClosed()) {
                        return Promise.reject(error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_CLOSED));
                    }
                    if (this.isDraining()) {
                        return Promise.reject(error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_DRAINING));
                    }
                    subject = subject || "";
                    if (subject.length === 0) {
                        return Promise.reject(error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.BAD_SUBJECT));
                    }
                    opts.timeout = opts.timeout || 1000;
                    if (opts.timeout < 1) {
                        return Promise.reject(new error_ts_9.NatsError("timeout", error_ts_9.ErrorCode.INVALID_OPTION));
                    }
                    if (opts.noMux) {
                        const inbox = protocol_ts_2.createInbox();
                        const sub = this.subscribe(inbox, { max: 1, timeout: opts.timeout });
                        this.publish(subject, data, { reply: inbox });
                        const d = util_ts_9.deferred();
                        (async () => {
                            for await (const msg of sub) {
                                d.resolve(msg);
                                break;
                            }
                        })().catch((err) => {
                            d.reject(err);
                        });
                        return d;
                    }
                    else {
                        const r = new request_ts_1.Request(this.protocol.muxSubscriptions, opts);
                        this.protocol.request(r);
                        try {
                            this.publish(subject, data, {
                                reply: `${this.protocol.muxSubscriptions.baseInbox}${r.token}`,
                                headers: opts.headers,
                            });
                        }
                        catch (err) {
                            r.cancel(err);
                        }
                        const p = Promise.race([r.timer, r.deferred]);
                        p.catch(() => {
                            r.cancel();
                        });
                        return p;
                    }
                }
                flush() {
                    return this.protocol.flush();
                }
                drain() {
                    if (this.isClosed()) {
                        return Promise.reject(error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_CLOSED));
                    }
                    if (this.isDraining()) {
                        return Promise.reject(error_ts_9.NatsError.errorForCode(error_ts_9.ErrorCode.CONNECTION_DRAINING));
                    }
                    this.draining = true;
                    return this.protocol.drain();
                }
                isClosed() {
                    return this.protocol.isClosed();
                }
                isDraining() {
                    return this.draining;
                }
                getServer() {
                    const srv = this.protocol.getServer();
                    return srv ? srv.listen : "";
                }
                status() {
                    const iter = new queued_iterator_ts_3.QueuedIterator();
                    this.listeners.push(iter);
                    return iter;
                }
                get info() {
                    return this.protocol.isClosed() ? undefined : this.protocol.info;
                }
                stats() {
                    return {
                        inBytes: this.protocol.inBytes,
                        outBytes: this.protocol.outBytes,
                        inMsgs: this.protocol.inMsgs,
                        outMsgs: this.protocol.outMsgs,
                    };
                }
            };
            exports_59("NatsConnectionImpl", NatsConnectionImpl);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/codec", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_60, context_60) {
    "use strict";
    var error_ts_10, encoders_ts_9;
    var __moduleName = context_60 && context_60.id;
    function StringCodec() {
        return {
            encode(d) {
                return encoders_ts_9.TE.encode(d);
            },
            decode(a) {
                return encoders_ts_9.TD.decode(a);
            },
        };
    }
    exports_60("StringCodec", StringCodec);
    function JSONCodec() {
        return {
            encode(d) {
                try {
                    if (d === undefined) {
                        d = null;
                    }
                    return encoders_ts_9.TE.encode(JSON.stringify(d));
                }
                catch (err) {
                    throw error_ts_10.NatsError.errorForCode(error_ts_10.ErrorCode.BAD_JSON, err);
                }
            },
            decode(a) {
                try {
                    return JSON.parse(encoders_ts_9.TD.decode(a));
                }
                catch (err) {
                    throw error_ts_10.NatsError.errorForCode(error_ts_10.ErrorCode.BAD_JSON, err);
                }
            },
        };
    }
    exports_60("JSONCodec", JSONCodec);
    return {
        setters: [
            function (error_ts_10_1) {
                error_ts_10 = error_ts_10_1;
            },
            function (encoders_ts_9_1) {
                encoders_ts_9 = encoders_ts_9_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/bench", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nuid", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error"], function (exports_61, context_61) {
    "use strict";
    var types_ts_8, nuid_ts_3, util_ts_10, error_ts_11, Metric, Bench;
    var __moduleName = context_61 && context_61.id;
    function throughput(bytes, seconds) {
        return humanizeBytes(bytes / seconds);
    }
    function humanizeBytes(bytes, si = false) {
        const base = si ? 1000 : 1024;
        const pre = si
            ? ["k", "M", "G", "T", "P", "E"]
            : ["K", "M", "G", "T", "P", "E"];
        const post = si ? "iB" : "B";
        if (bytes < base) {
            return `${bytes.toFixed(2)} ${post}/sec`;
        }
        const exp = parseInt(Math.log(bytes) / Math.log(base) + "");
        let index = parseInt((exp - 1) + "");
        return `${(bytes / Math.pow(base, exp)).toFixed(2)} ${pre[index]}${post}/sec`;
    }
    function humanizeNumber(n) {
        return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    return {
        setters: [
            function (types_ts_8_1) {
                types_ts_8 = types_ts_8_1;
            },
            function (nuid_ts_3_1) {
                nuid_ts_3 = nuid_ts_3_1;
            },
            function (util_ts_10_1) {
                util_ts_10 = util_ts_10_1;
            },
            function (error_ts_11_1) {
                error_ts_11 = error_ts_11_1;
            }
        ],
        execute: function () {
            Metric = class Metric {
                constructor(name, duration) {
                    this.payload = 0;
                    this.msgs = 0;
                    this.bytes = 0;
                    this.name = name;
                    this.duration = duration;
                    this.date = Date.now();
                }
                toString() {
                    const sec = (this.duration) / 1000;
                    const mps = Math.round(this.msgs / sec);
                    const label = this.asyncRequests ? "asyncRequests" : "";
                    let minmax = "";
                    if (this.max) {
                        minmax = `${this.min}/${this.max}`;
                    }
                    return `${this.name}${label ? " [asyncRequests]" : ""} ${humanizeNumber(mps)} msgs/sec - [${sec.toFixed(2)} secs] ~ ${throughput(this.bytes, sec)} ${minmax}`;
                }
                toCsv() {
                    return `"${this.name}",${new Date(this.date).toISOString()},${this.lang},${this.version},${this.msgs},${this.payload},${this.bytes},${this.duration},${this.asyncRequests ? this.asyncRequests : false}\n`;
                }
                static header() {
                    return `Test,Date,Lang,Version,Count,MsgPayload,Bytes,Millis,Async\n`;
                }
            };
            exports_61("Metric", Metric);
            Bench = class Bench {
                constructor(nc, opts = {
                    msgs: 100000,
                    size: 128,
                    subject: "",
                    asyncRequests: false,
                    pub: false,
                    sub: false,
                    req: false,
                    rep: false,
                }) {
                    this.callbacks = false;
                    this.nc = nc;
                    this.callbacks = opts.callbacks || false;
                    this.msgs = opts.msgs || 0;
                    this.size = opts.size || 0;
                    this.subject = opts.subject || nuid_ts_3.nuid.next();
                    this.asyncRequests = opts.asyncRequests || false;
                    this.pub = opts.pub || false;
                    this.sub = opts.sub || false;
                    this.req = opts.req || false;
                    this.rep = opts.rep || false;
                    this.perf = new util_ts_10.Perf();
                    this.payload = this.size ? new Uint8Array(this.size) : types_ts_8.Empty;
                    if (!this.pub && !this.sub && !this.req && !this.rep) {
                        throw new Error("No bench option selected");
                    }
                }
                async run() {
                    this.nc.closed()
                        .then((err) => {
                        if (err) {
                            throw new error_ts_11.NatsError(`bench closed with an error: ${err.message}`, error_ts_11.ErrorCode.UNKNOWN, err);
                        }
                    });
                    if (this.callbacks) {
                        await this.runCallbacks();
                    }
                    else {
                        await this.runAsync();
                    }
                    return this.processMetrics();
                }
                processMetrics() {
                    const nc = this.nc;
                    const { lang, version } = nc.protocol.transport;
                    if (this.pub && this.sub) {
                        this.perf.measure("pubsub", "pubStart", "subStop");
                    }
                    const measures = this.perf.getEntries();
                    const pubsub = measures.find((m) => m.name === "pubsub");
                    const req = measures.find((m) => m.name === "req");
                    const pub = measures.find((m) => m.name === "pub");
                    const sub = measures.find((m) => m.name === "sub");
                    const stats = this.nc.stats();
                    const metrics = [];
                    if (pubsub) {
                        const { name, duration } = pubsub;
                        const m = new Metric(name, duration);
                        m.msgs = this.msgs * 2;
                        m.bytes = stats.inBytes + stats.outBytes;
                        m.lang = lang;
                        m.version = version;
                        m.payload = this.payload.length;
                        metrics.push(m);
                    }
                    if (pub) {
                        const { name, duration } = pub;
                        const m = new Metric(name, duration);
                        m.msgs = this.msgs;
                        m.bytes = stats.outBytes;
                        m.lang = lang;
                        m.version = version;
                        m.payload = this.payload.length;
                        metrics.push(m);
                    }
                    if (sub) {
                        const { name, duration } = sub;
                        const m = new Metric(name, duration);
                        m.msgs = this.msgs;
                        m.bytes = stats.inBytes;
                        m.lang = lang;
                        m.version = version;
                        m.payload = this.payload.length;
                        metrics.push(m);
                    }
                    if (req) {
                        const { name, duration } = req;
                        const m = new Metric(name, duration);
                        m.msgs = this.msgs * 2;
                        m.bytes = stats.inBytes + stats.outBytes;
                        m.lang = lang;
                        m.version = version;
                        m.payload = this.payload.length;
                        metrics.push(m);
                    }
                    return metrics;
                }
                async runCallbacks() {
                    const jobs = [];
                    if (this.req) {
                        const d = util_ts_10.deferred();
                        jobs.push(d);
                        const sub = this.nc.subscribe(this.subject, {
                            max: this.msgs,
                            callback: (_, m) => {
                                m.respond(this.payload);
                                if (sub.getProcessed() === this.msgs) {
                                    d.resolve();
                                }
                            },
                        });
                    }
                    if (this.sub) {
                        const d = util_ts_10.deferred();
                        jobs.push(d);
                        let i = 0;
                        const sub = this.nc.subscribe(this.subject, {
                            max: this.msgs,
                            callback: (_, msg) => {
                                i++;
                                if (i === 1) {
                                    this.perf.mark("subStart");
                                }
                                if (i === this.msgs) {
                                    this.perf.mark("subStop");
                                    this.perf.measure("sub", "subStart", "subStop");
                                    d.resolve();
                                }
                            },
                        });
                    }
                    if (this.pub) {
                        const job = (async () => {
                            this.perf.mark("pubStart");
                            for (let i = 0; i < this.msgs; i++) {
                                this.nc.publish(this.subject, this.payload);
                            }
                            await this.nc.flush();
                            this.perf.mark("pubStop");
                            this.perf.measure("pub", "pubStart", "pubStop");
                        })();
                        jobs.push(job);
                    }
                    if (this.req) {
                        const job = (async () => {
                            if (this.asyncRequests) {
                                this.perf.mark("reqStart");
                                const a = [];
                                for (let i = 0; i < this.msgs; i++) {
                                    a.push(this.nc.request(this.subject, this.payload, { timeout: 20000 }));
                                }
                                await Promise.all(a);
                                this.perf.mark("reqStop");
                                this.perf.measure("req", "reqStart", "reqStop");
                            }
                            else {
                                this.perf.mark("reqStart");
                                for (let i = 0; i < this.msgs; i++) {
                                    await this.nc.request(this.subject);
                                }
                                this.perf.mark("reqStop");
                                this.perf.measure("req", "reqStart", "reqStop");
                            }
                        })();
                        jobs.push(job);
                    }
                    await Promise.all(jobs);
                }
                async runAsync() {
                    const jobs = [];
                    if (this.req) {
                        const sub = this.nc.subscribe(this.subject, { max: this.msgs });
                        const job = (async () => {
                            for await (const m of sub) {
                                m.respond(this.payload);
                            }
                        })();
                        jobs.push(job);
                    }
                    if (this.sub) {
                        let first = false;
                        const sub = this.nc.subscribe(this.subject, { max: this.msgs });
                        const job = (async () => {
                            for await (const m of sub) {
                                if (!first) {
                                    this.perf.mark("subStart");
                                    first = true;
                                }
                            }
                            this.perf.mark("subStop");
                            this.perf.measure("sub", "subStart", "subStop");
                        })();
                        jobs.push(job);
                    }
                    if (this.pub) {
                        const job = (async () => {
                            this.perf.mark("pubStart");
                            for (let i = 0; i < this.msgs; i++) {
                                this.nc.publish(this.subject, this.payload);
                            }
                            await this.nc.flush();
                            this.perf.mark("pubStop");
                            this.perf.measure("pub", "pubStart", "pubStop");
                        })();
                        jobs.push(job);
                    }
                    if (this.req) {
                        const job = (async () => {
                            if (this.asyncRequests) {
                                this.perf.mark("reqStart");
                                const a = [];
                                for (let i = 0; i < this.msgs; i++) {
                                    a.push(this.nc.request(this.subject, this.payload, { timeout: 20000 }));
                                }
                                await Promise.all(a);
                                this.perf.mark("reqStop");
                                this.perf.measure("req", "reqStart", "reqStop");
                            }
                            else {
                                this.perf.mark("reqStart");
                                for (let i = 0; i < this.msgs; i++) {
                                    await this.nc.request(this.subject);
                                }
                                this.perf.mark("reqStop");
                                this.perf.measure("req", "reqStart", "reqStop");
                            }
                        })();
                        jobs.push(job);
                    }
                    await Promise.all(jobs);
                }
            };
            exports_61("Bench", Bench);
        }
    };
});
System.register("https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/internal_mod", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nats", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nuid", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/error", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/types", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/msg", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscription", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/subscriptions", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/transport", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/protocol", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/util", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/headers", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/heartbeats", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/muxsubscription", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/databuffer", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/options", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/request", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/authenticator", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/codec", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/nkeys", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/queued_iterator", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/parser", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/denobuffer", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/bench", "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/encoders"], function (exports_62, context_62) {
    "use strict";
    var __moduleName = context_62 && context_62.id;
    var exportedNames_1 = {
        "NatsConnectionImpl": true,
        "Nuid": true,
        "nuid": true,
        "ErrorCode": true,
        "NatsError": true,
        "Events": true,
        "DebugEvents": true,
        "Empty": true,
        "MsgImpl": true,
        "SubscriptionImpl": true,
        "Subscriptions": true,
        "setTransportFactory": true,
        "Connect": true,
        "ProtocolHandler": true,
        "INFO": true,
        "createInbox": true,
        "render": true,
        "extractProtocolMessage": true,
        "delay": true,
        "deferred": true,
        "timeout": true,
        "MsgHdrsImpl": true,
        "headers": true,
        "Heartbeat": true,
        "MuxSubscription": true,
        "DataBuffer": true,
        "checkOptions": true,
        "Request": true,
        "nkeyAuthenticator": true,
        "jwtAuthenticator": true,
        "credsAuthenticator": true,
        "JSONCodec": true,
        "StringCodec": true,
        "QueuedIterator": true,
        "Parser": true,
        "State": true,
        "Kind": true,
        "DenoBuffer": true,
        "MAX_SIZE": true,
        "readAll": true,
        "writeAll": true,
        "Bench": true,
        "Metric": true,
        "TE": true,
        "TD": true
    };
    function exportStar_4(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default" && !exportedNames_1.hasOwnProperty(n)) exports[n] = m[n];
        }
        exports_62(exports);
    }
    return {
        setters: [
            function (nats_ts_1_1) {
                exports_62({
                    "NatsConnectionImpl": nats_ts_1_1["NatsConnectionImpl"]
                });
            },
            function (nuid_ts_4_1) {
                exports_62({
                    "Nuid": nuid_ts_4_1["Nuid"],
                    "nuid": nuid_ts_4_1["nuid"]
                });
            },
            function (error_ts_12_1) {
                exports_62({
                    "ErrorCode": error_ts_12_1["ErrorCode"],
                    "NatsError": error_ts_12_1["NatsError"]
                });
            },
            function (types_ts_9_1) {
                exports_62({
                    "Events": types_ts_9_1["Events"],
                    "DebugEvents": types_ts_9_1["DebugEvents"],
                    "Empty": types_ts_9_1["Empty"]
                });
            },
            function (msg_ts_2_1) {
                exports_62({
                    "MsgImpl": msg_ts_2_1["MsgImpl"]
                });
            },
            function (subscription_ts_3_1) {
                exports_62({
                    "SubscriptionImpl": subscription_ts_3_1["SubscriptionImpl"]
                });
            },
            function (subscriptions_ts_2_1) {
                exports_62({
                    "Subscriptions": subscriptions_ts_2_1["Subscriptions"]
                });
            },
            function (transport_ts_2_1) {
                exports_62({
                    "setTransportFactory": transport_ts_2_1["setTransportFactory"]
                });
            },
            function (protocol_ts_3_1) {
                exports_62({
                    "Connect": protocol_ts_3_1["Connect"],
                    "ProtocolHandler": protocol_ts_3_1["ProtocolHandler"],
                    "INFO": protocol_ts_3_1["INFO"],
                    "createInbox": protocol_ts_3_1["createInbox"]
                });
            },
            function (util_ts_11_1) {
                exports_62({
                    "render": util_ts_11_1["render"],
                    "extractProtocolMessage": util_ts_11_1["extractProtocolMessage"],
                    "delay": util_ts_11_1["delay"],
                    "deferred": util_ts_11_1["deferred"],
                    "timeout": util_ts_11_1["timeout"]
                });
            },
            function (headers_ts_2_1) {
                exports_62({
                    "MsgHdrsImpl": headers_ts_2_1["MsgHdrsImpl"],
                    "headers": headers_ts_2_1["headers"]
                });
            },
            function (heartbeats_ts_2_1) {
                exports_62({
                    "Heartbeat": heartbeats_ts_2_1["Heartbeat"]
                });
            },
            function (muxsubscription_ts_2_1) {
                exports_62({
                    "MuxSubscription": muxsubscription_ts_2_1["MuxSubscription"]
                });
            },
            function (databuffer_ts_3_1) {
                exports_62({
                    "DataBuffer": databuffer_ts_3_1["DataBuffer"]
                });
            },
            function (options_ts_2_1) {
                exports_62({
                    "checkOptions": options_ts_2_1["checkOptions"]
                });
            },
            function (request_ts_2_1) {
                exports_62({
                    "Request": request_ts_2_1["Request"]
                });
            },
            function (authenticator_ts_2_1) {
                exports_62({
                    "nkeyAuthenticator": authenticator_ts_2_1["nkeyAuthenticator"],
                    "jwtAuthenticator": authenticator_ts_2_1["jwtAuthenticator"],
                    "credsAuthenticator": authenticator_ts_2_1["credsAuthenticator"]
                });
            },
            function (codec_ts_4_1) {
                exports_62({
                    "JSONCodec": codec_ts_4_1["JSONCodec"],
                    "StringCodec": codec_ts_4_1["StringCodec"]
                });
            },
            function (nkeys_ts_6_1) {
                exportStar_4(nkeys_ts_6_1);
            },
            function (queued_iterator_ts_4_1) {
                exports_62({
                    "QueuedIterator": queued_iterator_ts_4_1["QueuedIterator"]
                });
            },
            function (parser_ts_2_1) {
                exports_62({
                    "Parser": parser_ts_2_1["Parser"],
                    "State": parser_ts_2_1["State"],
                    "Kind": parser_ts_2_1["Kind"]
                });
            },
            function (denobuffer_ts_2_1) {
                exports_62({
                    "DenoBuffer": denobuffer_ts_2_1["DenoBuffer"],
                    "MAX_SIZE": denobuffer_ts_2_1["MAX_SIZE"],
                    "readAll": denobuffer_ts_2_1["readAll"],
                    "writeAll": denobuffer_ts_2_1["writeAll"]
                });
            },
            function (bench_ts_1_1) {
                exports_62({
                    "Bench": bench_ts_1_1["Bench"],
                    "Metric": bench_ts_1_1["Metric"]
                });
            },
            function (encoders_ts_10_1) {
                exports_62({
                    "TE": encoders_ts_10_1["TE"],
                    "TD": encoders_ts_10_1["TD"]
                });
            }
        ],
        execute: function () {
        }
    };
});
System.register("file:///home/masud/go/src/github.com/nats-io/nats.ws/src/nats-base-client", ["https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-7/nats-base-client/internal_mod"], function (exports_63, context_63) {
    "use strict";
    var __moduleName = context_63 && context_63.id;
    function exportStar_5(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default") exports[n] = m[n];
        }
        exports_63(exports);
    }
    return {
        setters: [
            function (internal_mod_ts_2_1) {
                exportStar_5(internal_mod_ts_2_1);
            }
        ],
        execute: function () {
        }
    };
});
System.register("file:///home/masud/go/src/github.com/nats-io/nats.ws/src/ws_transport", ["file:///home/masud/go/src/github.com/nats-io/nats.ws/src/nats-base-client"], function (exports_64, context_64) {
    "use strict";
    var nats_base_client_ts_1, VERSION, LANG, WsTransport;
    var __moduleName = context_64 && context_64.id;
    return {
        setters: [
            function (nats_base_client_ts_1_1) {
                nats_base_client_ts_1 = nats_base_client_ts_1_1;
            }
        ],
        execute: function () {
            VERSION = "1.0.0-108";
            LANG = "nats.ws";
            WsTransport = class WsTransport {
                constructor() {
                    this.version = VERSION;
                    this.lang = LANG;
                    this.connected = false;
                    this.done = false;
                    this.socketClosed = false;
                    this.yields = [];
                    this.signal = nats_base_client_ts_1.deferred();
                    this.closedNotification = nats_base_client_ts_1.deferred();
                }
                async connect(hp, options) {
                    const connected = false;
                    const connLock = nats_base_client_ts_1.deferred();
                    this.options = options;
                    const proto = this.options.ws ? "ws" : "wss";
                    this.socket = new WebSocket(`${proto}://${hp.hostname}:${hp.port}`);
                    this.socket.binaryType = "arraybuffer";
                    this.socket.onopen = () => {
                        this.connected = true;
                        connLock.resolve();
                    };
                    this.socket.onmessage = (me) => {
                        this.yields.push(new Uint8Array(me.data));
                        this.signal.resolve();
                    };
                    this.socket.onclose = (evt) => {
                        this.socketClosed = true;
                        let reason;
                        if (this.done)
                            return;
                        if (!evt.wasClean) {
                            reason = new Error(evt.reason);
                        }
                        this._closed(reason);
                    };
                    this.socket.onerror = (e) => {
                        const evt = e;
                        const err = new nats_base_client_ts_1.NatsError(evt.message, nats_base_client_ts_1.ErrorCode.UNKNOWN);
                        if (!connected) {
                            connLock.reject(err);
                        }
                        else {
                            this._closed(err);
                        }
                    };
                    return connLock;
                }
                disconnect() {
                    this._closed(undefined, true);
                }
                async _closed(err, internal = true) {
                    if (!this.connected)
                        return;
                    if (this.done)
                        return;
                    this.closeError = err;
                    if (!err) {
                        while (!this.socketClosed && this.socket.bufferedAmount > 0) {
                            console.log(this.socket.bufferedAmount);
                            await nats_base_client_ts_1.delay(100);
                        }
                    }
                    this.done = true;
                    try {
                        this.socket.close(err ? 1002 : 1000, err ? err.message : undefined);
                    }
                    catch (err) {
                    }
                    if (internal) {
                        this.closedNotification.resolve(err);
                    }
                }
                get isClosed() {
                    return this.done;
                }
                [Symbol.asyncIterator]() {
                    return this.iterate();
                }
                async *iterate() {
                    while (true) {
                        if (this.yields.length === 0) {
                            await this.signal;
                        }
                        const yields = this.yields;
                        this.yields = [];
                        for (let i = 0; i < yields.length; i++) {
                            if (this.options.debug) {
                                console.info(`> ${nats_base_client_ts_1.render(yields[i])}`);
                            }
                            yield yields[i];
                        }
                        if (this.done) {
                            break;
                        }
                        else if (this.yields.length === 0) {
                            yields.length = 0;
                            this.yields = yields;
                            this.signal = nats_base_client_ts_1.deferred();
                        }
                    }
                }
                isEncrypted() {
                    return !this.options.ws;
                }
                send(frame) {
                    if (this.done) {
                        return Promise.resolve();
                    }
                    try {
                        this.socket.send(frame.buffer);
                        if (this.options.debug) {
                            console.info(`< ${nats_base_client_ts_1.render(frame)}`);
                        }
                        return Promise.resolve();
                    }
                    catch (err) {
                        if (this.options.debug) {
                            console.error(`!!! ${nats_base_client_ts_1.render(frame)}: ${err}`);
                        }
                        return Promise.reject(err);
                    }
                }
                close(err) {
                    return this._closed(err, false);
                }
                closed() {
                    return this.closedNotification;
                }
            };
            exports_64("WsTransport", WsTransport);
        }
    };
});
System.register("file:///home/masud/go/src/github.com/nats-io/nats.ws/src/connect", ["file:///home/masud/go/src/github.com/nats-io/nats.ws/src/nats-base-client", "file:///home/masud/go/src/github.com/nats-io/nats.ws/src/ws_transport"], function (exports_65, context_65) {
    "use strict";
    var nats_base_client_ts_2, ws_transport_ts_1;
    var __moduleName = context_65 && context_65.id;
    function connect(opts = {}) {
        nats_base_client_ts_2.setTransportFactory(() => {
            return new ws_transport_ts_1.WsTransport();
        });
        return nats_base_client_ts_2.NatsConnectionImpl.connect(opts);
    }
    exports_65("connect", connect);
    return {
        setters: [
            function (nats_base_client_ts_2_1) {
                nats_base_client_ts_2 = nats_base_client_ts_2_1;
            },
            function (ws_transport_ts_1_1) {
                ws_transport_ts_1 = ws_transport_ts_1_1;
            }
        ],
        execute: function () {
        }
    };
});
System.register("file:///home/masud/go/src/github.com/nats-io/nats.ws/src/mod", ["file:///home/masud/go/src/github.com/nats-io/nats.ws/src/nats-base-client", "file:///home/masud/go/src/github.com/nats-io/nats.ws/src/connect"], function (exports_66, context_66) {
    "use strict";
    var __moduleName = context_66 && context_66.id;
    var exportedNames_2 = {
        "connect": true
    };
    function exportStar_6(m) {
        var exports = {};
        for (var n in m) {
            if (n !== "default" && !exportedNames_2.hasOwnProperty(n)) exports[n] = m[n];
        }
        exports_66(exports);
    }
    return {
        setters: [
            function (nats_base_client_ts_3_1) {
                exportStar_6(nats_base_client_ts_3_1);
            },
            function (connect_ts_1_1) {
                exports_66({
                    "connect": connect_ts_1_1["connect"]
                });
            }
        ],
        execute: function () {
        }
    };
});

const __exp = __instantiate("file:///home/masud/go/src/github.com/nats-io/nats.ws/src/mod", false);
export const connect = __exp["connect"];
export const NatsConnectionImpl = __exp["NatsConnectionImpl"];
export const Nuid = __exp["Nuid"];
export const nuid = __exp["nuid"];
export const ErrorCode = __exp["ErrorCode"];
export const NatsError = __exp["NatsError"];
export const Msg = __exp["Msg"];
export const NatsConnection = __exp["NatsConnection"];
export const PublishOptions = __exp["PublishOptions"];
export const RequestOptions = __exp["RequestOptions"];
export const ServerInfo = __exp["ServerInfo"];
export const ServersChanged = __exp["ServersChanged"];
export const Status = __exp["Status"];
export const Subscription = __exp["Subscription"];
export const SubscriptionOptions = __exp["SubscriptionOptions"];
export const Events = __exp["Events"];
export const DebugEvents = __exp["DebugEvents"];
export const Empty = __exp["Empty"];
export const MsgImpl = __exp["MsgImpl"];
export const SubscriptionImpl = __exp["SubscriptionImpl"];
export const Subscriptions = __exp["Subscriptions"];
export const setTransportFactory = __exp["setTransportFactory"];
export const Transport = __exp["Transport"];
export const Connect = __exp["Connect"];
export const ProtocolHandler = __exp["ProtocolHandler"];
export const INFO = __exp["INFO"];
export const createInbox = __exp["createInbox"];
export const Timeout = __exp["Timeout"];
export const Deferred = __exp["Deferred"];
export const render = __exp["render"];
export const extractProtocolMessage = __exp["extractProtocolMessage"];
export const delay = __exp["delay"];
export const deferred = __exp["deferred"];
export const timeout = __exp["timeout"];
export const MsgHdrs = __exp["MsgHdrs"];
export const MsgHdrsImpl = __exp["MsgHdrsImpl"];
export const headers = __exp["headers"];
export const Heartbeat = __exp["Heartbeat"];
export const PH = __exp["PH"];
export const MuxSubscription = __exp["MuxSubscription"];
export const DataBuffer = __exp["DataBuffer"];
export const checkOptions = __exp["checkOptions"];
export const Request = __exp["Request"];
export const Authenticator = __exp["Authenticator"];
export const nkeyAuthenticator = __exp["nkeyAuthenticator"];
export const jwtAuthenticator = __exp["jwtAuthenticator"];
export const credsAuthenticator = __exp["credsAuthenticator"];
export const Codec = __exp["Codec"];
export const JSONCodec = __exp["JSONCodec"];
export const StringCodec = __exp["StringCodec"];
export const Dispatcher = __exp["Dispatcher"];
export const QueuedIterator = __exp["QueuedIterator"];
export const ParserEvent = __exp["ParserEvent"];
export const Parser = __exp["Parser"];
export const State = __exp["State"];
export const Kind = __exp["Kind"];
export const DenoBuffer = __exp["DenoBuffer"];
export const MAX_SIZE = __exp["MAX_SIZE"];
export const readAll = __exp["readAll"];
export const writeAll = __exp["writeAll"];
export const Bench = __exp["Bench"];
export const Metric = __exp["Metric"];
export const BenchOpts = __exp["BenchOpts"];
export const TE = __exp["TE"];
export const TD = __exp["TD"];
export const nkeys = __exp["nkeys"];
