const _ = require("lodash");
const assert = require("chai").assert;
const utils = require("..");

describe("@turbot/utils", function() {
  describe("data", function() {
    describe("sensitiveKey", function() {
      const tests = [
        ["safe name", "hello", false],
        ["prefixed name", "$password", true],
        ["unsafe name", "password", true],
        ["unsafe name, mixed case", "PasSwOrd", true],
        ["prefixed name, but prefixes set to []", "$password", false, { prefixes: [] }],
        ["custom prefix char", "#password", true, { prefixes: ["#"] }],
        ["custom prefix string - full match", "##password", true, { prefixes: ["##"] }],
        ["custom prefix string - partial non-match", "#password", false, { prefixes: ["##"] }]
      ];

      tests.forEach(test => {
        it(`${test[0]}: ${test[1]}`, function() {
          assert.equal(utils.data.sensitiveKey(test[1], test[3]), test[2]);
        });
      });
    });

    describe("sanitize", function() {
      describe("basic", function() {
        const currentTime = new Date();

        const testData = [
          {
            title: "String data is returned as is",
            data: "notObject",
            expectedResult: "notObject"
          },

          {
            title: "Numeric data is returned as is",
            data: 123,
            expectedResult: 123
          },

          {
            title: "Dates are handled explicitly as objects and returned as is",
            data: currentTime,
            expectedResult: currentTime
          },

          {
            title: "The $ref field (Swagger) is safe to publish only by exception",
            data: { $ref: "defaultExceptionShowMe" },
            options: { exceptions: ["$ref"] },
            expectedResult: { $ref: "defaultExceptionShowMe" }
          },

          {
            title: "Exceptions should override prefixes and data should not be hidden",
            data: { $field: "showMe", "^field": "showMe" },
            options: { exceptions: ["$field", "^field"], prefixes: ["#", "^"] },
            expectedResult: { $field: "showMe", "^field": "showMe" }
          },

          {
            title: "$ is a default prefix and should hide data",
            data: { $sensitiveField: "defaultPrefixHideMe" },
            expectedResult: { $sensitiveField: "<sensitive>" }
          },

          {
            title: "$$ is encrypted representation, but should still be sensitive",
            data: {
              $password: "defaultPrefixHideMe",
              $$password: "abcd1234base64"
            },
            expectedResult: { $password: "<sensitive>", $$password: "<sensitive>" }
          },

          {
            title: "sensitiveValue option can be used to change the output",
            data: {
              $sensitive: "hide me"
            },
            options: { sensitiveValue: "__hidden__" },
            expectedResult: { $sensitive: "__hidden__" }
          },

          {
            title: "Fields with matching prefixes should hide data",
            data: { "#field": "hideMe", "^field": "hideMe" },
            options: { prefixes: ["#", "^"] },
            expectedResult: { "#field": "<sensitive>", "^field": "<sensitive>" }
          },

          {
            title: "Fields that match the list of sensitive keys (case insensitive) should hide data",
            data: { PASSWORD: "hideMe", aws_Secret_Access_key: "hideMe", sourcerecord: "hideMe" },
            expectedResult: {
              PASSWORD: "<sensitive>",
              aws_Secret_Access_key: "<sensitive>",
              sourcerecord: "<sensitive>"
            }
          },

          {
            title: "Each element in array should be checked",
            data: [
              { PASSWORD: "hideMe", aws_Secret_Access_key: "hideMe", sourcerecord: "hideMe" },
              { "#field": "hideMe", "^field": "hideMe" }
            ],
            options: { prefixes: ["#", "^"] },
            expectedResult: [
              { PASSWORD: "<sensitive>", aws_Secret_Access_key: "<sensitive>", sourcerecord: "<sensitive>" },
              { "#field": "<sensitive>", "^field": "<sensitive>" }
            ]
          },

          {
            title: "Each object property at each level should be checked",
            data: {
              obj1: {
                obj1a: { PASSWORD: "hideMe", aws_Secret_Access_key: "hideMe", sourcerecord: "hideMe" },
                obj1b: { date: currentTime }
              },
              obj2: { "#field": "hideMe", "^field": "hideMe" }
            },
            options: { prefixes: ["#", "^"] },
            expectedResult: {
              obj1: {
                obj1a: { PASSWORD: "<sensitive>", aws_Secret_Access_key: "<sensitive>", sourcerecord: "<sensitive>" },
                obj1b: { date: currentTime }
              },
              obj2: { "#field": "<sensitive>", "^field": "<sensitive>" }
            }
          },

          {
            title: "Works with numeric keys",
            data: {
              23: "twenty-three",
              200: {
                210: "two hundred and ten"
              }
            },
            expectedResult: {
              23: "twenty-three",
              200: {
                210: "two hundred and ten"
              }
            }
          }
        ];

        testData.forEach(test => {
          it(`${test.title}`, function() {
            const expectedResult = utils.data.sanitize(test.data, test.options || {});
            assert.deepEqual(test.expectedResult, expectedResult);
          });
        });

        it("sensitive value as message", function() {
          const value = utils.data.sanitize({ message: "password", data: { name: "victor" } });
          assert.equal(value.data, "<sensitive>");
        });
      });

      describe("cloning", function() {
        it("clones by default", function() {
          let input = { one: 1, two: 2, deep: { $sensitive: "hideme" } };
          let output = utils.data.sanitize(input);
          assert.equal(input.two, 2);
          assert.equal(output.two, 2);
          assert.equal(output.deep.$sensitive, "<sensitive>");
          input.two = 22;
          assert.equal(input.two, 22);
          assert.equal(output.two, 2);
        });

        it("does not clone if clone: false", function() {
          let input = { one: 1, two: 2, deep: { $sensitive: "hideme" } };
          let output = utils.data.sanitize(input, { clone: false });
          assert.equal(input.two, 2);
          assert.equal(output.two, 2);
          assert.equal(output.deep.$sensitive, "<sensitive>");
          input.two = 22;
          assert.equal(input.two, 22);
          assert.equal(output.two, 22);
        });
      });

      describe("symbol key is preserved (used by winston logs)", function() {
        let input, output;
        let rootSymbol = Symbol("test@root");
        let deepSymbol = Symbol("test@deep");
        let sensitiveSymbol = Symbol("$sensitive");
        before(function() {
          input = { deep: {} };
          input[rootSymbol] = "data in symbol key";
          input.deep[deepSymbol] = "data in symbol key";
          input.deep[sensitiveSymbol] = "sensitive symbol key";
          output = utils.data.sanitize(input);
        });
        it("root level symbol key is preserved", function() {
          assert.equal(output[rootSymbol], input[rootSymbol]);
        });
        it("deep symbol key is preserved", function() {
          assert.equal(output.deep[deepSymbol], input.deep[deepSymbol]);
        });
        it("symbol with sensitive name is preserved (only strings are considered sensitive)", function() {
          assert.equal(output.deep[sensitiveSymbol], input.deep[sensitiveSymbol]);
        });
      });

      describe("Error objects are preserved", function() {
        let input, output;
        before(function() {
          try {
            throw new Error("test-error");
          } catch (e) {
            //input = errors.internal("wrapped-error", e);
            input = e;
          }
          output = utils.data.sanitize(input, { clone: false });
        });
        it("matches", function() {
          assert.equal(input.message, output.message);
          assert.equal(input.stack, output.stack);
          assert.equal(input.name, output.name);
        });
      });

      describe("circular data does not break", function() {
        let input, output;
        before(function() {
          input = { one: 1, two: 2 };
          input.cycle = input;
        });
        it("cyclic input unchanged", function() {
          assert.strictEqual(input, input.cycle);
        });
        it("works and maintains cycles if clone=true and breakCircular=false (default)", function() {
          output = utils.data.sanitize(input);
          assert.strictEqual(output.cycle, output);
          assert.deepEqual(input, output);
        });
        it("cyclic input unchanged - 2", function() {
          assert.strictEqual(input, input.cycle);
        });
        it("works and maintains cycles if clone=false and breakCircular=false", function() {
          output = utils.data.sanitize(input, { clone: false, breakCircular: false });
          assert.strictEqual(output.cycle, output);
          assert.strictEqual(input, output);
        });
        it("cyclic input unchanged", function() {
          assert.strictEqual(input, input.cycle);
        });
        it("works and breaks cycles if clone=true and breakCircular=true", function() {
          output = utils.data.sanitize(input, { clone: true, breakCircular: true });
          assert.equal(output.cycle, "[Circular]");
          assert.notDeepEqual(input, output);
        });
        it("cyclic input unchanged - 3", function() {
          assert.strictEqual(input, input.cycle);
        });
        it("breaks cycles (and mutates input) if clone=false and breakCircular=true", function() {
          output = utils.data.sanitize(input, { clone: false, breakCircular: true });
          assert.equal(output.cycle, "[Circular]");
          assert.strictEqual(input, output);
        });
        it("cyclic input CHANGED!", function() {
          assert.notStrictEqual(input, input.cycle);
        });
      });
    });

    describe("sanitize string", function() {
      const testData = [
        { description: "a", input: { text: "a", opts: {} }, expected: "a" },
        {
          description: "Turbot uri",
          input: { text: "tmod:@turbot/turbot#/control/types/ctFunc", opts: { replacementChar: "_" } },
          expected: "tmod__turbot_turbot__control_types_ctFunc"
        },
        {
          description: "Turbot uri with custom allowed Regex",
          input: {
            text: "tmod:@turbot/turbot#/control/types/ctFunc",
            opts: { allowedCharsRegex: /[A-Za-z0-9@/]/, replacementChar: "_" }
          },
          expected: "tmod_@turbot/turbot_/control/types/ctFunc"
        }
      ];

      testData.forEach(test => {
        it(`${test.description}`, function() {
          const output = utils.data.sanitizeString(test.input.text, test.input.opts);
          assert.equal(output, test.expected);
        });
      });
    });

    describe("cyclic and delete keys", function() {
      const a = "a";
      const b = { b: "b" };
      const c = {
        a: a,
        b: b
      };

      // b & c have circular reference
      b.c = c;

      const d = {
        a: a,
        f: "f"
      };

      const at = {
        a: a,
        d: d,
        ".turbot": c
      };

      const bt = {
        a: a,
        d: d,
        ".turbot": {
          a: a,
          ".turbot": {
            d: d
          }
        },
        z: {
          z: "z",
          ".turbot": {
            foo: "foo"
          }
        }
      };

      it("able to sanitize cyclic object", function() {
        // None of these should cause stack overflow/infinite loop
        utils.data.sanitize(c, { breakCircular: true });
        utils.data.sanitize(bt, { breakCircular: true });
        utils.data.sanitize(at, { breakCircular: true });
      });
    });
  });
});
