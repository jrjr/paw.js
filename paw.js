// Please host this on a separate origin from the entities utilizing this wallet serving only this static content so that it wont be affected by XSS issues.

function PAW(cb, options) {
  if (options == undefined) {
    options={};
  }
  this.options = options || {};
  this.options.whitelisted_origins = options.hasOwnProperty('whitelisted_origins') ? options.whitelisted_origins : []; //whitelisted origins that can use this wallet for identities
  this.options.algorithms = options.hasOwnProperty('algorithms') ? options.algorithms : null; // in order of preference, via webcrypto. Would be awesome if webcrypto supports more public key algorithms such as ed25519
  this.options.hash = options.hasOwnProperty('hash') ? options.hash : null;
  this.options.require_encrypted_private_keys = options.hasOwnProperty('require_encrypted_private_keys') ? options.require_encrypted_private_keys : false; // webcrypto will need to support this in the future, this would be akin to 2FA
  this.options.can_signup = options.hasOwnProperty('can_signup') ? options.can_signup : true; // orgs that don't want to enable signup can in the future have an option to import a keypair with an identity
  this.options.two_factor = options.hasOwnProperty('two_factor') ? options.two_factor : "none"; // "none", "optional", "required". optional and required cannot be used with webcrypto
  this.options.method = options.hasOwnProperty('method') ? options.method : "webcrypto"; // "webcrypto" or "NaCl"
  this.options.debug = options.hasOwnProperty('debug') ? options.debug : true; // orgs that don't want to enable signup can in the future have an option to import a keypair with an identity

  this.ready = false;
  this.source;
  this.the_origin;
  var that = this;
  this.callback_notifier = cb;
  if (this.options.debug) {
    console.log("cb callback_notifier: ");
    console.log(this.options);
  }
  //data is of
  // { "origin": "http://example.com",
  //   "keypairs" : {
  //       {"bob@gmail.com", "pubkey"},
  //       {"john@gmail.com", "pubkey"},
  //     }
  // }

  window.addEventListener("message", function(message) {
      // save the source
      that.source = message.source;
      that.the_origin=message.origin;
      if (that.options.debug) {
        console.log("got new message:");
        console.log(message.origin);
        console.log(message.data);
      }
      // we only want to listen for one message from the sender as there could be other windows open to this origin
      window.removeEventListener("message", this);

      if (message.data == "PAW_auth") {
        if (that.options.debug) {
          console.log("attempting load identities for origin");
        }
        that.ready=true;  // means we've received one message request for a login/signup operation
        that.callback_notifier(that.the_origin);
      }
    });

  this.set_identities = function(updatedobject, cb) {
    if (that.options.debug) {
      console.log("trying to save identities to IndexedDB");
    }
    callOnStore(function (store) {
      var oresult = store.put(updatedobject);
      oresult.onsuccess = cb;
    })
  }

  this.get_identities = function(cb) {
    callOnStore(function (store) {
      if (that.options.debug) {
        console.log("trying to load origin: " + that.the_origin);
      }
      var getData = store.get(that.the_origin);
      getData.onsuccess = cb;
      })
    }

  this.sign_for_operation = function(operation, ident, cb) {
    // first we need to get the identities
    this.get_identities(function(event) {
      var thekeypair = event.target.result.keypairs[ident];
      var signthis=[];
      var temprandom = window.crypto.getRandomValues(new Uint8Array(32));
      if (that.options.debug) {
        console.log(event.target.result);
        console.log("random: ");
        console.log(temprandom);
      }

      var randomstring = btoa(U8AToString(temprandom));
      var timestamp = new Date().getTime();

      // build the object string we want to sign
      //  signthis.push({"origin":the_origin});
      signthis.push({"identity":ident});
      signthis.push({"timestamp": timestamp});
      signthis.push({"pubkeystring": "pubkey"});
      signthis.push({"random": randomstring});
      signthis.push({"action": operation});

      // we must include the public key in the signed message, so we need to export it
      window.crypto.subtle.exportKey(
        "jwk",
        thekeypair.publicKey
      )
      .then(function(keydata) {
        //add the publickey to the data that's being signed
        signthis.push({"publickey": keydata});

        if (that.options.debug) {
          console.log(keydata);
          console.log("signing this: ");
          console.log(signthis);
          console.log(JSON.stringify(signthis));
        }

        // sign it
        var s = generate_signature(thekeypair.privateKey, JSON.stringify(signthis));

        s.then(function(signature){

          tempsig=signature;
          thesignature = U8AToString(new Uint8Array(signature));
          // build the postmessage
          var postbackmessage = {"data": signthis, "signature": btoa(thesignature)}

          if (that.options.debug) {
            console.log("signature is:");
            console.log(signature);
            console.log(new Uint8Array(signature));
            console.log(thesignature);
            console.log(btoa(thesignature));
            console.log(atob(btoa(thesignature)));
            console.log(stringToU8A(atob(btoa(thesignature))));
            console.log("sending this back to the origin");
            console.log(postbackmessage);
          }

          cb(postbackmessage);
        });
        s.catch(function(err){
          console.error(err);
        });
      })
      .catch(function(err){
        console.error(err);
      });
    });
  }

  this.send = function(response, cb) {
    this.source.postMessage(response, this.the_origin);

    if (that.options.debug) {
      console.log(this.source);
      console.log(this.the_origin);
      console.log("sent response");
    }

    cb(false);
  }

  this.create = function(identity, cb) {
    if (that.options.debug) {
      console.log("in create");
      console.log(identity);
    }

    // basic checks of input
    if(identity != null && identity != '') {
      // create keypair for new identity
      var r = generate_keypair();
      r.then(function(key) {
        var thekeypair=key;

        if (that.options.debug) {
          console.log("generated keypair");
          console.log(key);
          console.log(key.publicKey);
          console.log(key.privateKey);
          console.log("getting identities");
        }

        // get the current identities and add the new one and save it
        that.get_identities(function(event) {
          var tempidentities = event.target.result;

          if (tempidentities && 'keypairs' in tempidentities && 'origin' in tempidentities) {
            tempidentities.keypairs[identity] = thekeypair;
          }
          else {
            tempidentities = {};
            tempidentities.keypairs = {};
            tempidentities.origin = that.the_origin;
            tempidentities.keypairs[identity] = thekeypair;
          }

          if (that.options.debug) {
            console.log("trying to store: ");
            console.log(tempidentities);
          }

          that.set_identities(tempidentities, function (event) {
            if (that.options.debug) {
              console.log("saved the identities, now doing callback");
            }
            cb(identity);
          });
        });
      });
      r.catch(function(err){
        console.error(err);
      });
    }
    else {
      console.log("identity is empty!");
    }
  }

  this.remove = function(identity, cb) {
    this.get_identities(function(event) {
      var obj = event.target.result;
      var gb = Object.keys(obj.keypairs).reduce(function (object, key) {
        if (key !== identity) {
          object[key] = obj.keypairs[key];
        }
        return object;
      }, {});

      var newob = {};
      newob.origin = obj.origin;
      newob.keypairs = gb;

      if (that.options.debug) {
        console.log(obj);
        console.log(newob);
      }

      that.set_identities(newob, function (event) {
        if (that.options.debug) {
          console.log("saved identities");
        }
        cb();
      });
    });
  }

  function callOnStore(fn_) {
    var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

    var open = indexedDB.open("PAWDatabase", 1);

    open.onupgradeneeded = function() {
      var db = open.result;
      var store = db.createObjectStore("PAWObjectStore", {keyPath: "origin"});
    };

    open.onsuccess = function() {
      var db = open.result;
      var tx = db.transaction("PAWObjectStore", "readwrite");
      var store = tx.objectStore("PAWObjectStore");

      fn_(store)

      tx.oncomplete = function() {
        db.close();
      };
    }
  }

  function generate_signature(key_to_sign_with, data_to_sign) {
    return window.crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32
      },
      key_to_sign_with,
      new TextEncoder().encode(data_to_sign)
    );
  }

  function generate_keypair() {
      return window.crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: 4096,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: {name: "SHA-512"},
        },
        false, //whether the key is extractable
        ["sign", "verify"]
      );
    }

  function stringToU8A(s) {
    return Uint8Array.from(s,(x)=>x.charCodeAt(0));
  }

  function U8AToString(u) {
    return String.fromCharCode.apply(null,u);
  }

}
