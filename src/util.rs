// nickel
use nickel::{Request, Response, MiddlewareResult};
use nickel::status::StatusCode::{self, Forbidden};

// hyper
use hyper::header;
use hyper::header::{Authorization, Bearer};

use crypto::sha2::Sha256;
use jwt::{Header, Registered, Token};


use AUTH_SECRET;

pub fn authenticator<'mw>(request: &mut Request, response: Response<'mw>) -> MiddlewareResult<'mw> {
	// Check if we are getting an OPTIONS request
	if request.origin.method.to_string() == "OPTIONS".to_string() {
		// The middleware should not be used for OPTIONS, so continue
		response.next_middleware()

	} else {
		// We do not want to apply the middleware to the login route
		if request.origin.uri.to_string() == "/login".to_string() {
			response.next_middleware()
		} else {
			// Get the full Authorization header from the incoming request headers
			let auth_header = match request.origin.headers.get::<Authorization<Bearer>>() {
				Some(header) => header,
				None => panic!("No authorization header found")
			};

			// Format the header to only take the value
			let jwt = header::HeaderFormatter(auth_header).to_string();

			// We don't need the Bearer part,
			// so get whatever is after an index of 7
			let jwt_slice = &jwt[7..];

			// Parse the token
			let token = Token::<Header, Registered>::parse(jwt_slice).unwrap();

			// Get the secret key as bytes
			let secret = AUTH_SECRET.as_bytes();

			// Verify the token
			if token.verify(&secret, Sha256::new()) {
				response.next_middleware()
			} else {
				response.error(Forbidden, "Access denied")
			}
		}
	}
}