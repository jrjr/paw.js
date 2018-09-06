var express = require('express');
var router = express.Router();
var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('sqlite.db');
const crypto = require('crypto');
const njwk = require('node-jwk');
const { TextEncoder, TextDecoder } = require('text-encoding');
var atob = require('atob');

const timestamp_threshold = 30000; // 10, 20, or 30 seconds??
const session_threshold = 86400000; // session expires in this amount of time: 24 hours
//var jwk2pem = require('pem-jwk').jwk2pem;
var authrequired   = [authChecker];
var csrftokenrequired = [csrfCheck];

function csrfCheck(req, res, next) {
  // TODO check if body param exists and is not empty
  if (! crypto.timingSafeEqual(Buffer.from(req.body.csrf_token), Buffer.from(req.session.csrf_token))) {
    res.status(403);
    res.render('error', { message: "bad csrf token" });
  }
  else {
    next();
  }
}

function authChecker(req, res, next) {
  if (!(req.session.user)) {
    console.log("no valid session");
    res.redirect("/auth");
  }
  else if ((new Date().getTime()) - req.session.creation_time >session_threshold) {
    req.session.destroy(function (err) {
      console.log("session expired");
      res.redirect("/auth");
    });

    //req.session.user=undefined;
    // delete req.session.user;
    // req.session.creation_time=undefined;
    // delete req.session.creation_time;
  }
  else {
    console.log("valid session for: " + req.session.user);
    next();
  }
}

router.use(function(req, res, next) {
  // inject default headers
  res.header('X-Frame-Options', 'DENY');
  //  res.header('Strict-Transport-Security', 'max-age=31536000 ; includeSubDomains');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-XSS-Protection', '1; mode=block');

  next();
});

router.get('/', authrequired, function(req, res, next) {
  var context = {
    "title": 'Diary App',
    "user": req.session.user,
    "csrftoken": req.session.csrf_token,
    "entries" : []
  };
  try {
    db.get("select * from users where username=?",req.session.user, function (err, row) {
      if (err) throw err;
      console.log(row);
      var entries = JSON.parse(row.diary_entries);
      context.entries = entries.reverse();
      res.render('index', context);
    });
  } catch (error) {
    console.log(error);
  }

});

router.post('/delete', authrequired, csrftokenrequired, function(req, res, next) {
  console.log("deleting a diary entry");
  var body = req.body;
  console.log(body);

  try {
    db.get("select * from users where username=?",req.session.user, function (err, row) {
      if (err) throw err;
      console.log(row);
      var entries = JSON.parse(row.diary_entries);
      // var v = {};
      // v.time = new Date().getTime();
      // v.data = body.entry;
      var deletedentry;
      var found=-1;
      // entries.push(v);
      for(var i = 0; i < entries.length; i++)
      {
        if(entries[i].time == body.deletethis)
        {
          found=i;
          break;
        }
      }

      if (found >=0) {
        console.log("found item to delete");
        console.log(i);
        console.log(entries);
        deletedentry = entries.splice(i, 1);
        console.log(deletedentry);

        db.run("update users set diary_entries=? where id=?", JSON.stringify(entries), row.id, function (err) {
          if (err) throw err;
          console.log("updated database entries, lastID: "+ this.lastID);
          res.redirect('/');
        });
      }
      else {
        console.log("no item found to delete");
        res.redirect("/");
      }

    });
  } catch (error) {
    console.log(error);
  }
//  console.log("no item found to delete");

  //res.redirect('/');
});

router.post('/', authrequired, csrftokenrequired, function(req, res, next) {
  console.log("adding a diary entry");
  var body = req.body;
  console.log(body);
  console.log(body.entry);

  try {
    db.get("select * from users where username=?",req.session.user, function (err, row) {
      if (err) throw err;
      console.log(row);
      var entries = JSON.parse(row.diary_entries);
      var v = {};
      v.time = new Date().getTime();
      v.data = body.entry;
      entries.push(v);

      db.run("update users set diary_entries=? where id=?", JSON.stringify(entries), row.id, function (err) {
        if (err) throw err;
        console.log("updated database entries, lastID: "+ this.lastID);
        res.redirect('/');
      });
    });
  } catch (error) {
    console.log(error);
  }

});

router.post('/auth', function(req, res, next) {
  console.log("in auth");
  //  console.log(req.body);
  var data = req.body.data;
  var signature = req.body.signature;
  console.log(data);
  console.log("signature");
  console.log(signature);
  //console.log(JSON.stringify(signature));
  //var hashes = crypto.getHashes();
  //console.log(hashes);

  var verify = crypto.createVerify('sha512');

  console.log("the data");
  console.log(JSON.stringify(data));
  console.log(new TextEncoder().encode(JSON.stringify(data)));
  //verify.update(JSON.stringify(data));
  var g = Buffer.from(new TextEncoder().encode(JSON.stringify(data)));
  console.log(g);
  verify.update(g);

  var publicKey = njwk.JWK.fromObject(data[data.length-1].publickey);
  //  var v = jwk2pem(data[data.length-1].publickey);
  //console.log(v);
  console.log("pem");
  console.log(publicKey.key.toPublicKeyPEM());

  try {
    //  console.log(verify.verify({key: v, saltLength: 128, padding: crypto.constants.RSA_PKCS1_PSS_PADDING}, JSON.stringify(signature)));
    console.log("signature after in buffer, base64");
    console.log(Buffer.from(signature, 'base64'));
    //console.log(Buffer.from(b64DecodeUnicode(signature)));
    console.log(Buffer.from(atob(signature)));

    //  console.log(b64DecodeUnicode(signature));
    console.log(atob(signature));

    //b64DecodeUnicode(signature);
    //console.log("signature base64 decoded");
    //console.log(b64DecodeUnicode(signature));
    //  console.log(new TextEncoder().encode(b64DecodeUnicode(signature)));
    //console.log(Buffer.from(new TextEncoder().encode(b64DecodeUnicode(signature))));
    var isvalid = verify.verify({key: publicKey.key.toPublicKeyPEM(), saltLength: 32, padding: crypto.constants.RSA_PKCS1_PSS_PADDING}, Buffer.from(signature, 'base64'));
    console.log("isvalid signature: "+ isvalid);
    //console.log(verify.verify({key: publicKey.key.toPublicKeyPEM(), saltLength: 128, padding: crypto.constants.RSA_PKCS1_PSS_PADDING}, b64DecodeUnicode(signature)));
    //  console.log(verify.verify(publicKey.key.toPublicKeyPEM(), signature, "base64"));

    // if signature is valid
    if (isvalid) {
      console.log("timestamp: " + data[1].timestamp);
      var now = new Date().getTime();
      console.log("node now: "+ new Date().getTime());
      var dif = now - data[1].timestamp;
      console.log("time diff: "+ dif);

      // check timestamp within valid window
      if (dif > -timestamp_threshold && dif < timestamp_threshold) {
        console.log("timestamp is within window threshold, continuing");

        //  var user_already_exists = check_if_user_exists(data[0].identity);
        db.get("select * from users where username=?",data[0].identity, function (err, row) {
          if (err) throw err;
          console.log("row");
          console.log(row);
          var requested_operation = data[4].action;// either add key or signup

          if (requested_operation === "signup") {
            console.log("doing signup");
            if (row) {
              console.log("user already exists");
              console.log("Can't signup when an identity is already used, user already exists");
              res.json({"redirect": "/auth", "error": "3"});
            }
            else { // user does not exist
              console.log("user does not yet exist");
              console.log("Signing user up");
              const hash = crypto.createHash('sha256');
              hash.update(publicKey.key.toPublicKeyPEM());
              var fingerprint = hash.digest('hex');
              console.log("fingerprint: " + fingerprint);
              var active_pubkeys = [];
              active_pubkeys.push({"fingerprint": fingerprint, "time_added": new Date().getTime() });
              //      CREATE TABLE users active_pubkey_fingerprints text, pending_pubkey_fingerprints text, diary_entries text , can_add_new_keys integer);
              // active_pubkey_fingerprints = [{fingerprint: [fingerprint], time_added: [timestamp]}]
              db.run("insert into users (username, active_pubkey_fingerprints, pending_pubkey_fingerprints, diary_entries, can_add_new_keys ) values (?,?,?,?,?)", data[0].identity, JSON.stringify(active_pubkeys) , JSON.stringify([]),JSON.stringify([]), 0, function (err) {
                if (err) throw err;
                console.log("inserted new user, lastID: "+ this.lastID);

                // give a valid login session
                req.session.regenerate(function (err) {
                  req.session.user = data[0].identity;
                  req.session.creation_time = new Date().getTime();

                  // create CSRF token
                  crypto.randomBytes(32, function (err, buf)  {
                    if (err) throw err;
                    console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
                    req.session.csrf_token = buf.toString('hex');
                    res.json({"redirect": "/"});
                  });
                });

              });
            }
          }
          else if (requested_operation === "addkey") {
            console.log("attempting to add key to the existing user");
            // check if user is allowing to add new keys
            // TODO
          }
          else if (requested_operation === "login") {
            console.log("doing login");
            if (row) {
              console.log("user already exists");
              // get publickey fingerprint
              const hash = crypto.createHash('sha256');
              hash.update(publicKey.key.toPublicKeyPEM());
              var fingerprint = hash.digest('hex');
              console.log("fingerprint: " + fingerprint);
              var bfp = Buffer.from(fingerprint);

              list_of_fingerprints = JSON.parse(row.active_pubkey_fingerprints);
              console.log(list_of_fingerprints);
              console.log(typeof list_of_fingerprints);
              var found=false;
              found = list_of_fingerprints.some( function (fp) {
                console.log(bfp);
                console.log(fp.fingerprint);
                if (crypto.timingSafeEqual(bfp, Buffer.from(fp.fingerprint))) {
                  console.log("fingerprints match");
                  console.log(fp.fingerprint);
                  return true;
                }
              });

              if (found) {
                console.log("granting use a session");
                req.session.regenerate(function (err) {
                  req.session.user = data[0].identity;
                  req.session.creation_time = new Date().getTime();
                  crypto.randomBytes(32, function (err, buf)  {
                    if (err) throw err;
                    console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
                    req.session.csrf_token = buf.toString('hex');
                    res.json({"redirect": "/"});
                  });
                });
              }
              else {
                // not allowed to login with that key
                console.log("fingerprint not found, not allowed to login");
                res.json({"redirect": "/auth", "error": "6"});
              }
            }
            else {
              console.log("user does not yet exist");
              res.json({"redirect": "/auth", "error": "5"});
            }
          }
          else {
            console.log("unknown operation");
            res.json({"redirect": "/auth", "error": "4"});
          }
        });
      } else {
        console.log("timestamp outside of window threshold");
        res.json({"redirect": "/auth", "error": "2"});
      }
    }
    else {
      console.log("not a valid signature");
      res.json({"redirect": "/auth", "error": "1"});
    }
  } catch (error) {
    console.log(error);
  }
  console.log("end");
});

router.get('/auth', function(req, res, next) {
  if (req.session.user) {
    res.redirect("/");
  }
  else {
    res.render('login', { title: 'PAW.js Demo: Diary' });
  }
});

router.post('/logout', authrequired, csrftokenrequired, function(req, res, next) {
  req.session.destroy(function (err) {
    console.log("logged out user");
    res.redirect("/auth");
  });
});

router.get('/reset', function(req, res, next) {
  res.render('index', { title: 'signup' });
});

router.get('/keys', function(req, res, next) {
  res.render('index', { title: 'signup' });
});

router.get('/approvekey', function(req, res, next) {
  res.render('index', { title: 'signup' });
});

module.exports = router;
