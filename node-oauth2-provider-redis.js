

var redis = require('redis')
  , OAuth2Provider = require('oauth2-provider').OAuth2Provider;

var db = redis.createClient ();


exports.oap = new OAuth2Provider ({crypt_key: 'encryption secret', sign_key: 'signing secret'});

// If the user is not authorized, first send them to the login page
exports.oap.on ('enforce_login', function (req, res, authorize_url, next) {
	console.log ('enforce_login');
	
	if (req.session.user) {
		next (req.session.user);
	} else {
		res.writeHead (303, { Location: '/u/login?next=' + encodeURIComponent (authorize_url) });
		res.end ();
	}
});

// render the authorize form with the submission URL
// use two submit buttons named "allow" and "deny" for the user's choice
exports.oap.on ('authorize_form', function (req, res, client_id, authorize_url) {
	console.log ('authorize_form');
	res.end('<html>this app wants to access your account... ' +
			  '<form method="post" action="' + authorize_url + '">' +
			  '<button name="allow">Allow</button><button name="deny">Deny</button></form>');
});

exports.oap.on ('create_access_token', function (user_id, client_id, next) {
	console.log ('create_access_token');
	next (null);
});

exports.oap.on('save_access_token', function (user_id, client_id, access_token) {
	console.log ('save_access_token: ' + access_token);
  	console.log('saving access token %s for user_id=%s client_id=%s', access_token, user_id, client_id);
});

// an access token was received in a URL query string parameter or HTTP header
exports.oap.on('access_token', function (req, token, next) {
	console.log ('access_token');
	console.dir (token);

	req.session.user = token.user_id;
	req.session.data = token.extra_data;
	
	next();
});


// save the generated grant code for the current user
exports.oap.on ('save_grant', function (req, client_id, code, next) {
	console.log ('save_grant: ' + client_id + ' code: ' + code);

	var vals = ['oauth:grantforcode:' + code, 'account', req.session.user, 'client_id', client_id]
	db.hmset (vals, function (err) {
	
		if (err) {
			next (new Error ('error saving grant: ' + err));
			return;
		}
		next();
	});
});


// remove the grant when the access token has been sent
exports.oap.on ('remove_grant', function (user_id, client_id, code) {
	console.log ('remove_grant');

	var key = 'oauth:grantforcode:' + code;
	db.del (key, function (err) {
		if (err) {
			console.log ('unable to remove grant: ' + err);
			return;
		}
	});
});

// find the user for a particular grant
exports.oap.on('lookup_grant', function (client_id, client_secret, code, next) {
	console.log ('lookup_grant');

	var key = 'oauth:client:' + client_id + ':secret';
	db.get (key, function (err, result) {
		if (err) {
			next (new Error ('error looking up grant: ' + err));
			return;
		}
		if (!result) {
			next (new Error ('no grants for client_id: ' + client_id));
			return;
		}
		if (result != client_secret) {
			next (new Error ('client_id/client_secret are invalid'));
			return;
		}

		key = 'oauth:grantforcode:' + code;
		db.hgetall (key, function (err, result) {
			if (err) {
				next (new Error ('error looking up user/client for grant code: ' + err));
				return;
			}

			if (result.client_id != client_id) {
				next (new Error ('supplied client_id did not match grant client id.'));
				return;
			} 
			return next (null, result.account);
		});
	});
});


