#!/usr/bin/env node

import { MongoClient } from 'mongodb';
import { MongoServerError } from 'mongodb';
import fs from 'fs'; 
import express from 'express';
import { engine } from 'express-handlebars';
import http from 'http';
import axios from 'axios';
import {
    pjclHex2BitArray,
    pjclBitArray2Hex,
    pjclHex2BigInt,
    pjclBigInt2Hex,
    pjclRBG128Instantiate,
    pjclRBG128Reseed,
    pjclCurve_P256,
    pjclSHA256,
    pjclRBGGen,
    pjclECDSAGenKeyPair,
    pjclECDSAValidatePublicKey,
    pjclECDSAVerifyMsg,
    pjclECDSASignMsg,
    pjclStRndHex
} from 'pjcl/pjcl-with-argument-checking.js';
import {
    jsonUtilsObject2Hex,
    jsonUtilsHex2Object,
    jsonUtilsObject2BitArray
} from "./json-utils.js";

// setting up a good source of entropy
//
const rbgStateObject = new Object();
const rbgSecurityStrength = 128;
const reseedPeriod = 604093; // a little over 10 minutes
//
function getDevRandomBits(bitLength, f) {
    const byteLength = bitLength / 8;
    const buf = Buffer.alloc(byteLength); 
    (function fillBuf(bufPos) {
        let remaining = byteLength - bufPos;
        if (remaining == 0) {
            f(buf.toString('hex'));
            return;
        }
        fs.open('/dev/random', 'r', function(err, fd) {
            if (err) throw new Error(err);
            fs.read(fd, buf, bufPos, remaining, 0, function(err, bytesRead) {
                if (err) throw new Error(err);
                bufPos += bytesRead;
                fs.close(fd, function(err) {
                    if (err) throw new Error(err);
                    fillBuf(bufPos);
                });
            });
        });
    })(0);
}
//
let rbgStateInitialized = false;
//
getDevRandomBits(rbgSecurityStrength, function(hex) {
    pjclRBG128Instantiate(rbgStateObject, pjclHex2BitArray(hex));
    rbgStateInitialized = true;            
    reseedPeriodically(reseedPeriod);
});
//
function reseedPeriodically(period) {
    setTimeout(getDevRandomBits, period, rbgSecurityStrength, function(hex) {
        pjclRBG128Reseed(rbgStateObject, pjclHex2BitArray(hex));
        reseedPeriodically(period);
    });
}

const connectionString = "mongodb://localhost:27017";
const mongoClient = new MongoClient(connectionString);
const debugClient = new MongoClient(connectionString);

// the configuration of this server consists of:
// - a certificate chain obtained from the Trust Registry,
//   comprising the RSTA CA certificate and the Trust Registry self-signed certificate
// - the private key associated with RSTA CA certificate,
//   used to sign objects and respond with the signature and the certificate chain
// in this demo, the object that is signed is called unsignedCert_object
//
// this function is only called if there is no configuration
//
async function createConfig() {
    const issuerKeyPair = pjclECDSAGenKeyPair(rbgStateObject, pjclCurve_P256);
    const d_hex = pjclBigInt2Hex(issuerKeyPair.d);
    const Q_x_hex = pjclBigInt2Hex(issuerKeyPair.Q.x);
    const Q_y_hex = pjclBigInt2Hex(issuerKeyPair.Q.y);
    const issuerPubKey = {Q_x_hex, Q_y_hex};
    const targetUrl = 'http://localhost:3053/cert-chain-request';
    const response = await axios.post(targetUrl, issuerPubKey, {
        headers: {
	    'Content-Type': 'application/json',
	    'x-ca-name': 'RSTA'
	}
    });
    const certChain = response.data;
    return {
	d_hex,
	certChain
    }
}

// alternative 1
//
let config = null;

// the configuration collection has a single document
// with _id field "singledocument" and a config field
//
async function createOrRetrieveConfig() {
    await mongoClient.connect();
    const database = mongoClient.db('hsmDb');
    const collection = database.collection('configuration');
    const query = { _id: "singleDocument" };
    const configDocument = await collection.findOne(query);
    if (configDocument) {
	return configDocument.config;
    }
    else {
	const createdConfig = await createConfig();
	try {
	    await collection.insertOne({
		_id: "singleDocument",
		config: createdConfig
	    });
	    return createdConfig;	    
	} catch (error) {
	    if (error.code === 11000) {
		throw new Error("race condition: a configuration must have just been created");
	    }
	    else {
		throw new Error("configuration failed");
	    }
	}
	finally {
	    await mongoClient.close();
	}
    }
}

// alternative 1
//
(async () => {
   config = await createOrRetrieveConfig();
})();

const app = express();
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set('views', './views');

http.createServer(app).listen(3054);
console.log("listening on port 3054");

app.use(express.static('static'));

app.use(express.json());

// Axios should handle this!!!
app.use(function(req,res,next) {
    if (
	!rbgStateInitialized
    ) {
        res.status(503).send('SERVER BUSY, TRY AGAIN LATER');
    }
    else {
        next();
    }
});

app.get('/', (req, res) => {
    res.redirect(303, '/hsm-home-page.html');
});

app.get('/hsm-home-page.html', (req, res) => {
    res.render('hsm-home-page.handlebars', {});
});

app.post('/sign-object', async (req, res) => {

    // alternative 2
    //
    // const config = await createOrRetrieveConfig();

    const toBeSigned_object = req.body;
    const toBeSigned = jsonUtilsObject2BitArray(toBeSigned_object);
    const d = pjclHex2BigInt(config.d_hex);
    const signature = pjclECDSASignMsg(rbgStateObject,pjclCurve_P256,d,toBeSigned);
    const signature_object = {
	r_hex: pjclBigInt2Hex(signature.r),
	s_hex: pjclBigInt2Hex(signature.s)
    };
    res.json({ signature: signature_object, certChain: config.certChain });
});

app.use(function(req,res) {
    res.status(404).send('NOT FOUND');
});
app.use(function(err,req,res,next) {
    console.log("Error: " + err.stack);
    res.status(500).send('INTERNAL ERROR');
});
