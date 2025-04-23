import crypto from "crypto";
import jsonwebtoken from "jsonwebtoken";

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const noirJwt = require("noir-jwt");

const maxSignedDataLength = 900;
const shaPrecomputeTillKeys = undefined;

const { publicKey: publicKeyPem, privateKey: privateKeyPem } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    // publicKeyEncoding: {
    //   type: "spki",
    //   format: "pem",
    // },
    // privateKeyEncoding: {
    //   type: "pkcs1",
    //   format: "pem",
    // },
  });

const token = jsonwebtoken.sign({ data: "foobar" }, privateKeyPem, {
  algorithm: "RS256",
});

const jwk = publicKeyPem.export({
  format: "jwk",
});

// Now use the JWK format for generateInputs
const inputs = noirJwt.generateInputs({
  jwt: token,
  pubkey: jwk,
  maxSignedDataLength,
  shaPrecomputeTillKeys,
});

console.log("inputs");
console.log(await inputs);

inputs.then((inputs: any) => {
  // Print all elements of data.storage on a single line
  console.log(inputs.data.storage.join(","));
});
