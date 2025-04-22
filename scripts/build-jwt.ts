//const noirJwt = require("noir-jwt");
//console.log(noirJwt);
//const { generateInputs } = require("noir-jwt");
import { generateKeyPairSync } from "crypto";
import jsonwebtoken from "jsonwebtoken";
import sshpk from "sshpk";

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const noirJwt = require("noir-jwt");

// const jwt =
//   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoxMjN9.HT1kBSdGFAznrhbs2hB6xjVDilMUmKA-_36n1pLLtFTKHoO1qmRkUcy9bJJwGuyfJ_dbzBMyBwpXMj-EXnKQQmKlXsiItxzLVIfC5qE97V6l6S0LzT9bzixvgolwi-qB9STp0bR_7suiXaON-EzBWFh0PzZi7l5Tg8iS_0_iSCQQlX5MSJW_-bHESTf3dfj5GGbsRBRsi1TRBzvxMUB6GhNsy6rdUhwoTkihk7pljISTYs6BtNoGRW9gVUzfA2es3zwBaynyyMeSocYet6WJri97p0eRnVGtHSWwAmnzZ-CX5-scO9uYmb1fT1EkhhjGhnMejee-kQkMktCTNlPsaUAJyayzdgEvQeo5M9ZrfjEnDjF7ntI03dck1t9Bgy-tV1LKH0FWNLq3dCJJrYdQx--A-I7zW1th0C4wNcDe_d_GaYopbtU-HPRG3Z1SPKFuX1m0uYhk9aySvkec66NBfvV2xEgo8lRZyNxntXkMdeJCEiLF1UhQvvSvmWaWC-0uRulYACn4H-tZiaK7zvpcPkrsfJ7iR_O1bxMPziKpsM4b7c7tmsEcOUZY-IHEI9ibd54_A1O72i08sCWKT5CXyG70MAPqyR0MFlcV7IuDtBW3LCqyvfsDVk4eIj8VcSU1OKQJ1Gl-CTOHEyN-ncV3NslVLaT9Q1C4E7uK2QpS8z0";
// const pubkey =
//   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCcjWidoIPNRc3IN1hoGeOdSvDkBDK3W3P7/4HxLf62nvUQVczL3FG+dG9KSRnzuvRoUi1o3TASO3Yn72FSfaLPE/JmOtpu/IGuB/oF/CrJqEHA/08n0xkNQK8kwdIqayKPS84PVOm8XomNijMpUCahqu9cGZDPhlgqD8PAxw4e1ZQSizWj0hTSCR78dmHAEr5oXryP6uD0Mw/KGKYel/KTMu00dShWPzHnJeLaYvKgMJKPN6pqhsWFQsNUDnKd9tgn3NSPeHECnnBbUxB2BeuVz72+HnyFWah3mpGH4Dr+9rjRXiPg2AYxgR3U93AEQ6osefxeIKUSCXWx1txNV07QzwFVag4vPBmrA9XktC7i5EP91wxUOsyzhG8geXKuDHmE+/7U3AsExHYFkBLqMnW92CaTeQ408xsRXjxWjSNHpfqhZVxGY5Eh8L3NVqgRg1LdnZYHpovi1iP4Zx2Z7Nb5F9ejuMsA+v/D0WL3c6bhwU8BKdD7YZDG2tpzq6PHt+NarGkcWWh9/p/SIJoZi+e35mjcUMfnRD8w/ouL0sTnxebT7xBCVucfRoMPA67USoChDpc+pNsdtsqlQOZMgpPZYfjIyCThv5mwjEKHnytBq46ULOFlHt0opplDANnDsvWwqEobhACZM+n2ZNtu36eoc3bC/Hak8ACEi5DixirF0w== miguel@MS90J8G8WL";
const maxSignedDataLength = 900;
const shaPrecomputeTillKeys = undefined;

// const { publicKey, privateKey } = generateKeyPairSync("rsa", {
//   modulusLength: 2048,
//   publicKeyEncoding: {
//     type: "spki",
//     format: "pem",
//   },
//   privateKeyEncoding: {
//     type: "pkcs8",
//     format: "pem",
//   },
// });

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

console.log("PRIVATE KEY");
console.log(privateKey);

console.log("PUBLIC KEY");
console.log(publicKey);

const privKey = sshpk.parseKey(privateKey, "pem");
console.log("PRIVATE KEYYY");
console.log(privKey);
const pubKey = sshpk.parseKey(publicKey, "pem");
console.log("PUBLIC KEYYY");
console.log(pubKey);
console.log(pubKey.toString("ssh"));

const token = jsonwebtoken.sign({ data: "foobar" }, privateKey, {
  algorithm: "RS256",
});
console.log("TOKEN");
console.log(token);

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

// const pubKey = sshpk.parseKey(publicKey, "pem").toString("ssh");
// console.log("PUBLIC KEY");
// console.log(pubKey);

// const inputs = noirJwt.generateInputs({
//   jwt: token,
//   pubkey: {
//     kty: "RSA",
//     n: sshpk.parseKey(publicKey, "pem").toString("ssh"),
//     e: "AQAB",
//   },
//   maxSignedDataLength,
//   shaPrecomputeTillKeys,
// });

console.log("inputs");
console.log(await inputs);

inputs.then((inputs: any) => {
  // Print all elements of data.storage on a single line
  console.log(inputs.data.storage.join(","));
});
