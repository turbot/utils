/**
 * is this string JSON
 * @param str
 * @returns {boolean}
 */
const isJson = str => {
  try {
    JSON.parse(str);
  } catch (e) {
    return false;
  }
  return true;
};

/**
 * Return all sets of matched capture groups from the regex test
 * If the regex is not global, just the first match groups will be returned
 * @param testString
 * @param regex
 * @param capturingGroupNumbers (array of 1-based capture group numbers)
 */
function getRegexCaptureGroups(testString, regex, capturingGroupNumbers) {
  // if capturingGroupNumbers is not array, make it one
  capturingGroupNumbers = Array.isArray(capturingGroupNumbers) ? capturingGroupNumbers : [capturingGroupNumbers];
  let regexResult;
  // if regex is not global, it will only find first set of matches, so just return this
  if (!regex.global) {
    regexResult = regex.exec(testString);
    return [capturingGroupNumbers.map(c => regexResult[c] || "")];
  }

  // otherwise return all matches
  const matches = [];
  while ((regexResult = regex.exec(testString))) {
    matches.push(capturingGroupNumbers.map(c => regexResult[c] || ""));
  }
  return matches;
}

module.exports = {
  isJson,
  getRegexCaptureGroups
};
