import { generateKeyPairSync } from "crypto";
import jsonwebtoken from "jsonwebtoken";
import sshpk from "sshpk";

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const noirJwt = require("noir-jwt");

const maxSignedDataLength = 900;
const shaPrecomputeTillKeys = undefined;

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

const pubKey = sshpk.parseKey(publicKey, "pem");

const token = jsonwebtoken.sign({ data: "foobar" }, privateKey, {
  algorithm: "RS256",
});

const inputs = noirJwt.generateInputs({
  jwt: token,
  pubkey: {
    kty: "RSA",
    n: pubKey.toString("ssh").split(" ")[1], // Extract the base64 encoded modulus
    e: "AQAB", // Default RSA exponent 65537 in base64
  },
  maxSignedDataLength,
  shaPrecomputeTillKeys,
});

console.log("inputs");
console.log(await inputs);

inputs.then((inputs: any) => {
  // Print all elements of data.storage on a single line
  console.log(inputs.data.storage.join(","));
});
