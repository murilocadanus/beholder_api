// nickel
use nickel::{Request, Response, MiddlewareResult};

// hyper
use hyper::header;
use hyper::header::{Authorization, Bearer};

use jwt::{Header, Registered, Token};