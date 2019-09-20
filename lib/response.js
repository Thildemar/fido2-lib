"use strict";

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

const validator = require("./validator");

const parser = require("./parser");

const lockSym = Symbol();
/**
 * The base class of {@link Fido2AttestationResult} and {@link Fido2AssertionResult}
 * @property {Map} authnrData Authenticator data that was parsed and validated
 * @property {Map} clientData Client data that was parsed and validated
 * @property {Map} expectations The expectations that were used to validate the result
 * @property {Object} request The request that was validated
 * @property {Map} audit A collection of audit information, such as useful warnings and information. May be useful for risk engines or for debugging.
 * @property {Boolean} audit.validExpectations Whether the expectations that were provided were complete and valid
 * @property {Boolean} audit.validRequest Whether the request message was complete and valid
 * @property {Boolean} audit.complete Whether all fields in the result have been validated
 * @property {Set} audit.journal A list of the fields that were validated
 * @property {Map} audit.warning A set of warnigns that were generated while validating the result
 * @property {Map} audit.info A set of informational fields that were generated while validating the result. Includes any x509 extensions of the attestation certificate during registration.
 */

class Fido2Result {
  constructor(sym) {
    if (sym !== lockSym) {
      throw new Error("Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
    }

    validator.attach(this);
  }

  parse() {
    // TODO: id
    this.clientData = parser.parseClientResponse(this.request);
  }

  validate() {
    var _this = this;

    return _asyncToGenerator(function* () {
      // clientData, except type
      yield _this.validateRawClientDataJson();
      yield _this.validateOrigin();
      yield _this.validateChallenge();
      yield _this.validateTokenBinding();
      yield _this.validateId(); // authenticatorData, minus attestation

      yield _this.validateRawAuthnrData();
      yield _this.validateRpIdHash();
      yield _this.validateFlags();
    })();
  }

  create(req, exp) {
    var _this2 = this;

    return _asyncToGenerator(function* () {
      if (typeof req !== "object") {
        throw new TypeError("expected 'request' to be object, got: " + typeof req);
      }

      if (typeof exp !== "object") {
        throw new TypeError("expected 'expectations' to be object, got: " + typeof exp);
      }

      _this2.expectations = parser.parseExpectations(exp);
      _this2.request = req; // validate that input expectations and request are complete and in the right format

      yield _this2.validateExpectations(); // parse and validate all the request fields (CBOR, etc.)

      yield _this2.parse();
      yield _this2.validate(); // ensure the parsing and validation went well

      yield _this2.validateAudit();
      return _this2;
    })();
  }

}
/**
 * A validated attesetation result
 * @extends {Fido2Result}
 */


class Fido2AttestationResult extends Fido2Result {
  constructor(sym) {
    super(sym);
    this.requiredExpectations = new Set(["origin", "challenge", "flags"]);
  }

  parse() {
    this.validateCreateRequest();
    super.parse();
    this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject);
  }

  validate() {
    var _this3 = this,
        _superprop_callValidate = (..._args) => super.validate(..._args);

    return _asyncToGenerator(function* () {
      yield _this3.validateCreateType();
      yield _this3.validateAaguid();
      yield _this3.validatePublicKey();
      yield _superprop_callValidate();
      yield _this3.validateAttestation();
      yield _this3.validateInitialCounter();
      yield _this3.validateCredId();
    })();
  }

  static create(req, exp) {
    return new Fido2AttestationResult(lockSym).create(req, exp);
  }

}
/**
 * A validated assertion result
 * @extends {Fido2Result}
 */


class Fido2AssertionResult extends Fido2Result {
  constructor(sym) {
    super(sym);
    this.requiredExpectations = new Set(["origin", "challenge", "flags", "prevCounter", "publicKey", "userHandle"]);
  }

  parse() {
    this.validateAssertionResponse();
    super.parse();
    this.authnrData = parser.parseAuthnrAssertionResponse(this.request);
  }

  validate() {
    var _this4 = this,
        _superprop_callValidate2 = (..._args2) => super.validate(..._args2);

    return _asyncToGenerator(function* () {
      yield _this4.validateGetType();
      yield _superprop_callValidate2();
      yield _this4.validateAssertionSignature();
      yield _this4.validateUserHandle();
      yield _this4.validateCounter();
    })();
  }

  static create(req, exp) {
    return new Fido2AssertionResult(lockSym).create(req, exp);
  }

}

module.exports = {
  Fido2Result,
  Fido2AttestationResult,
  Fido2AssertionResult
};