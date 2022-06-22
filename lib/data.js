const _ = require("lodash");
const { serializeError } = require("serialize-error");

const SENSITIVE_OPTIONS = {
  // These fields will always be considered non-sensitive, even if they match
  // one of the rules below. Allows specific fields to be whitelisted when
  // sending data.
  exceptions: [],
  // Any field starting with one of these prefix strings will be treated as
  // sensitive. (Unless the full field name is a named exception.)
  prefixes: ["$"],
  // Any field with a name matching one of these keys will be treated as
  // sensitive. (Unless it's a named exception.)
  // Comparisons against these keys are case insensitive.
  keys: [
    // Standard
    "password",
    // AWS
    "secretaccesskey",
    "sessiontoken",
    "aws_secret_access_key",
    "aws_session_token",
    // GCP
    "key",
    // Azure
    "token",
    // Google
    "clientSecret",
    "access_token",
    // LDAP
    "sourcerecord",
    // SAML
    "cert",
    // SSH
    "privatekey",
    "secretValue"
  ],
  // If the field is sensitive, it will be replaced with this value.
  sensitiveValue: "<sensitive>",
  // By default, clone the data first, otherwise we mutate the passed in object.
  clone: true,
  // When a circular loop in the data is detected:
  //   if breakCircular is false (default), the cycle will be maintained
  //   if breakCircular is true, the data point will be replaced with "[Circular]"
  // WARNING: If breakCircular is true when clone is false the input will also
  // be mutated to break the circular data loop.
  breakCircular: false,
};

const _sensitiveKey = function (key, options) {
  if (!_.isString(key)) {
    return false;
  }
  // Exceptions are always non-sensitive
  if (options.exceptions.includes(key)) {
    return false;
  }
  // Prefixes are sensitive
  for (let p of options.prefixes) {
    if (key.startsWith(p)) {
      return true;
    }
  }
  for (let k of options.keys) {
    if (key.toLowerCase() == k.toLowerCase()) {
      return true;
    }
  }
  return false;
};

const _sanitize = function (data, options, seen = []) {
  if (!_.isObject(data)) {
    return options.clone ? _.clone(data) : data;
  }

  // TODO: hmm magic assumption that the sensitive data is in the field called 'data'
  // this is to match our log entries
  if (data.message && data.data) {
    if (_sensitiveKey(data.message, options)) {
      data.data = SENSITIVE_OPTIONS.sensitiveValue;
      return data;
    }
  }
  const keys = Object.keys(data);
  if (keys.length == 0) {
    return options.clone ? _.clone(data) : data;
  }
  seen.push(data);
  for (const k of keys) {
    if (_sensitiveKey(k, options)) {
      data[k] = options.sensitiveValue;
    } else {
      let circular = false;
      for (const p of seen) {
        if (p === data[k]) {
          circular = p;
          break;
        }
      }
      if (circular) {
        if (options.breakCircular) {
          data[k] = "[Circular]";
        } else {
          data[k] = circular;
        }
      } else {
        let workingData;
        if (data[k] instanceof Error) {
          workingData = serializeError(data[k]);
        } else {
          workingData = options.clone ? _.clone(data[k]) : data[k];
        }
        data[k] = _sanitize(workingData, options, seen);
      }
    }
  }
  // return options.clone ? _.clone(data) : data;
  return data;
};

const sensitiveKey = function (key, rawOptions = {}) {
  const options = _.chain(rawOptions).cloneDeep().defaults(SENSITIVE_OPTIONS).value();
  return _sensitiveKey(key, options);
};

const sanitize = function (data, rawOptions = {}) {
  const options = _.chain(rawOptions).cloneDeep().defaults(SENSITIVE_OPTIONS).value();

  const workingData = options.clone ? _.cloneDeep(data) : data;

  if (workingData[".turbot"]) {
    workingData[".turbot"] = "[Removed]";
  }
  return _sanitize(workingData, options);
};

const sanitizeString = function (str, opts) {
  if (opts == null) {
    opts = {};
  }
  _.defaults(opts, {
    allowedCharsRegex: /[A-Za-z0-9]/,
    maxLength: -1,
    replacementChar: "",
    trim: true,
  });
  let s = "";
  for (let c of Array.from(str)) {
    if (c.match(opts.allowedCharsRegex)) {
      s += c;
    } else {
      s += opts.replacementChar;
    }
    if (opts.maxLength >= 0 && s.length >= opts.maxLength) {
      break;
    }
  }
  if (opts.trim) {
    s = s.trim();
  }
  return s;
};

module.exports = {
  sanitizeString,
  sensitiveKey,
  sanitize,
};
