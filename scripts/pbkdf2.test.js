$(function () {
  'use strict';

  function getForgeProof(nodeObj) {
    return new Promise(function (resolve, reject) {
      var kdf = {
        node: nodeObj.node
      , type: nodeObj.type
      , kdf: 'PBKDF2'
      , algo: nodeObj.algo
      };

      // generate a password-based 16-byte key
      // note an optional message digest can be passed as the final parameter
      if (nodeObj.salt) {
        kdf.salt = Unibabel.bufferToBinaryString(Unibabel.hexToBuffer(nodeObj.salt));
      } else {
        // uses binary string
        kdf.salt = forge.random.getBytesSync(16);
      }
      kdf.iter = nodeObj.iter || Math.floor(Math.random() * 100) + 100;
      kdf.bits = nodeObj.bits;// || 128;

      // kdf.proof = forge.pkcs5.pbkdf2(nodeObj.secret, kdf.salt, kdf.iter, kdf.byteLen);

      // generate key asynchronously
      forge.pkcs5.pbkdf2(
        nodeObj.secret
      , kdf.salt
      , kdf.iter                                    // 100
      , (kdf.bits / 8)                              // 16
      , kdf.algo.replace(/\-/g, '').toLowerCase()  // sha256
      , function(err, derivedKey) {
        // do something w/derivedKey
        if (err) {
          reject(err);
          return;
        }

        kdf.salt = Unibabel.bufferToHex(Unibabel.binaryStringToBuffer(kdf.salt));
        kdf.proof = Unibabel.bufferToHex(Unibabel.binaryStringToBuffer(derivedKey));

        resolve(kdf);
      });
    });
  }

  function getWebCryptoProof(nodeObj) {
    var crypto = window.crypto;
    var Unibabel = window.Unibabel;
    var kdf = {
      node: nodeObj.node
    , type: nodeObj.type
    , kdf: 'PBKDF2'
    , algo: nodeObj.algo
    };

    // generate a password-based 16-byte key
    // note an optional message digest can be passed as the final parameter
    if (nodeObj.salt) {
      kdf.salt = Unibabel.hexToBuffer(nodeObj.salt);
    } else {
      // uses binary string
      kdf.salt = crypto.getRandomValues(new Uint8Array(16));
    }
    // 100 - probably safe even on a browser running from a raspberry pi using pure js ployfill
    // 10000 - no noticeable speed decrease on my MBP
    // 100000 - you can notice
    // 1000000 - annoyingly long
    // something a browser on a raspberry pi or old phone could do
    kdf.iter = nodeObj.iter || Math.floor(Math.random() * 100) + 100;
    kdf.bits = nodeObj.bits;// || 128;
    var aesname = "AES-CBC"; // AES-CTR is also popular
    var extractable = true;

    // First, create a PBKDF2 "key" containing the passphrase
    return crypto.subtle.importKey(
      "raw",
      Unibabel.utf8ToBuffer(nodeObj.secret),
      { "name": kdf.kdf },
      false,
      ["deriveKey"]).
    // Derive a key from the password
    then(function (passphraseKey) {
      var keyconf = {
        "name": kdf.kdf
      , "salt": kdf.salt
      , "iterations": kdf.iter
      , "hash": kdf.algo
      };
      return crypto.subtle.deriveKey(
        keyconf
      , passphraseKey
        // required to be 128 or 256 bits
      , { "name": aesname, "length": kdf.bits } // Key we want
      , extractable                               // Extractble
      , [ "encrypt", "decrypt" ]                  // For new key
      );
    }).
    // Export it so we can display it
    then(function (aesKey) {
      return crypto.subtle.exportKey("raw", aesKey).then(function (arrbuf) {
        kdf.proof = Unibabel.bufferToHex(new Uint8Array(arrbuf));
        return kdf;
      });
    }).
    catch(function (err) {
      window.alert("Key derivation failed: " + err.message);
    });
  }

  function run(conf) {
    var start = Date.now();
    var delta;
    var target = $('.js-target-time').val();
    var kdf = {
      secret: $('.js-secret').val()
    , iter: parseInt($('.js-iter').val(), 10)
    //, hash: $('.js-hash').val()
    , algo: $('.js-hash').val()
    , kdf: 'PBKDF2'
    , bits: parseInt($('.js-bits').val(), 10)
    };

    var promise;

    console.log('kdf');
    console.log(kdf);

    if (conf.which !== 'webcrypto') {
      promise = getForgeProof(kdf);
    } else {
      promise = getWebCryptoProof(kdf);
    }

    promise.then(function () {
      delta = ((Date.now() - start) / 1000);
      $('.js-stopwatch').val(delta + 's');
    }, function (err) {
      console.error('[UNHANDLED PROMISE]');
      console.error(err);
    });
  }

  $('body').on('click', '.js-forge-form', function (ev) {
    ev.preventDefault();
    ev.stopPropagation();

    console.log('forge');
    run({ which: 'forge' });
  });

  $('body').on('click', '.js-webcrypto-form', function (ev) {
    ev.preventDefault();
    ev.stopPropagation();

    console.log('webcrypto');
    run({ which: 'webcrypto' });
  });

  /*
  $('body').on('submit', 'form.js-form', function (ev) {
    ev.preventDefault();
    ev.stopPropagation();

    console.log('[CHECK TARGET SUBMIT] ev');
    console.log(ev);

    run();
  });
  */

  $('body').addClass('in');
});
