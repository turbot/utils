const ensureArray = (v) => {
  return v ? (Array.isArray(v) ? v : [v]) : [];
};

const uniq = (values) => [...new Set(values)];

module.exports = {
  data: require("./lib/data"),
  string: require("./lib/string"),
  ensureArray,
  uniq,
};
