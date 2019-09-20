/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place
"use strict";

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

function noneParseFn(attStmt) {
  if (Object.keys(attStmt).length !== 0) {
    throw new Error("'none' attestation format: attStmt had fields");
  }

  return new Map();
}

function noneValidateFn() {
  return _noneValidateFn.apply(this, arguments);
}

function _noneValidateFn() {
  _noneValidateFn = _asyncToGenerator(function* () {
    this.audit.journal.add("fmt");
    return true;
  });
  return _noneValidateFn.apply(this, arguments);
}

module.exports = {
  name: "none",
  parseFn: noneParseFn,
  validateFn: noneValidateFn
};