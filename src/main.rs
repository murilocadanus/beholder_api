#[macro_use]
extern crate nickel;

extern crate rustc_serialize;

#[macro_use(bson, doc)]
extern crate bson;
extern crate mongodb;

extern crate jwt;
extern crate hyper;
extern crate crypto;
extern crate chrono;

// nickel
use nickel::{Nickel, JsonBody, HttpRouter, MediaType, Request, Response, MiddlewareResult};
use nickel::status::StatusCode::{self, Forbidden};

// hyper
use hyper::header;
use hyper::header::{Authorization, Bearer};

// jwt
use std::default::Default;
use crypto::sha2::Sha256;
use jwt::{Header, Registered, Token};

// mongodb
use mongodb::{Client, ThreadedClient};
use mongodb::db::ThreadedDatabase;
use mongodb::error::Result as MongoResult;

// bson
use bson::{Bson, Document};
use bson::oid::ObjectId;

// rustc_serialize
use rustc_serialize::json::{Json, ToJson};

// chrono
use chrono::*;

static AUTH_SECRET: &'static str = "some_secret_key";

#[derive(RustcDecodable, RustcEncodable)]
struct UserLogin {
	email: String,
	password: String
}

#[derive(RustcDecodable, RustcEncodable)]
struct User {
	firstname: String,
	lastname: String,
	email: String
}

#[derive(RustcDecodable, RustcEncodable)]
struct PositionCoordinates {
	Type: String,
	coordinates: [f64; 2]
}

#[derive(RustcDecodable, RustcEncodable)]
struct PositionInput {
	ignicao: bool,
	entrada1: bool,
	entrada2: bool,
	entrada3: bool,
	entrada4: bool,
	entrada5: bool,
	entrada6: bool,
	entrada7: bool
}

#[derive(RustcDecodable, RustcEncodable)]
struct PositionOutput {
	saida0: bool,
	saida1: bool,
	saida2: bool,
	saida3: bool,
	saida4: bool,
	saida5: bool,
	saida6: bool,
	saida7: bool
}

#[derive(RustcDecodable, RustcEncodable)]
struct PositionFreeData {
	Analogico1: bool,
	Analogico2: bool,
	Analogico3: bool,
	Analogico4: bool,
	Horimetro: f32,
	AcelerometroX: f32,
	Digital1: bool,
	Digital2: bool,
	Digital3: bool,
	Digital4: bool,
	AcelerometroY: f32,
	Hodometro: f32,
	Rpm: u32,
	Freio: bool
}

#[derive(RustcDecodable, RustcEncodable)]
struct Position {
	id_equipamento: u32,
	veiculo: u32,
	placa: String,
	cliente: String,
	data_posicao: String,
	data_chegada: String,
	endereco: String,
	bairro: String,
	municipio: String,
	numero: String,
	estado: String,
	coordenadas: PositionCoordinates,
	pais: String,
	velocidade_via: u32,
	gps: bool,
	motorista_ibutton: String,
	entradas: PositionInput,
	saidas: PositionOutput,
	odometro_adicionado: bool,
	horimetro_adicionado: bool,
	inicio_rota: bool,
	fim_rota: bool,
	EmRe: bool,
	DadoLivre: PositionFreeData,
	tipo: String,
	lapso: String
}

fn get_data_string(result: MongoResult<Document>) -> Result<Json, String> {
	match result {
		Ok(doc) => Ok(Bson::Document(doc).to_json()),
		Err(e) => Err(format!("{}", e))
	}
}

fn authenticator<'mw>(request: &mut Request, response: Response<'mw>, ) -> MiddlewareResult<'mw> {
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

fn main() {
	let mut server = Nickel::new();
	let mut router = Nickel::router();

	router.post("/login", middleware! { |request|
		// Accept a JSON string that corresponds to the User struct
		let user = request.json_as::<UserLogin>().unwrap();

		// Get the email and password
		let email = user.email.to_string();
		let password = user.password.to_string();

		// Simple password checker
		if password == "secret".to_string() {

			let header: Header = Default::default();

			// For the example, we just have one claim
			// You would also want iss, exp, iat etc
			let claims = Registered {
				sub: Some(email.into()),
				..Default::default()
			};

			let token = Token::new(header, claims);

			// Sign the token
			let jwt = token.signed(AUTH_SECRET.as_bytes(), Sha256::new()).unwrap();

			format!("{}", jwt)

		} else {
			format!("Incorrect username or password")
		}
	});

	router.get("/users", middleware! { |request, mut response|
		// Connect to the database
		let client = Client::connect("localhost", 27017)
			.ok().expect("Error establishing connection.");

		// The users collection
		let coll = client.db("rust-users").collection("users");

		// Create cursor that finds all documents
		let mut cursor = coll.find(None, None).unwrap();

		// Opening for the JSON string to be returned
		let mut data_result = r#"{"data":["#.to_owned();

		for (i, result) in cursor.enumerate() {
			match get_data_string(result) {
				Ok(data) => {
					let string_data = if i == 0 {
						format!("{}", data)
					} else {
						format!("{},", data)
					};

					data_result.push_str(&string_data);
				},

				Err(e) => return response.send(format!("{}", e))
			}
		}

		// Close the JSON string
		data_result.push_str("]}");

		// Set the returned type as JSON
		response.set(MediaType::Json);

		// Send back the result
		format!("{}", data_result)
	});

	router.post("/users/new", middleware! { |request, response|
		// Accept a JSON string that corresponds to the User struct
		let user = request.json_as::<User>().unwrap();

		let firstname = user.firstname.to_string();
		let lastname = user.lastname.to_string();
		let email = user.email.to_string();

		// Connect to the database
		let client = Client::connect("localhost", 27017)
			.ok().expect("Error establishing connection.");

		// The users collection
		let coll = client.db("rust-users").collection("users");

		// Insert one user
		match coll.insert_one(doc! {
			"firstname" => firstname,
			"lastname" => lastname,
			"email" => email
		}, None) {
			Ok(_) => (StatusCode::Ok, "Item saved!"),
			Err(e) => return response.send(format!("{}", e))
		}
	});

	router.post("/positions/new", middleware! { |request, response|
		// Accept a JSON string that corresponds to the User struct
		let position = request.json_as::<Position>().unwrap();

		let lat = position.coordenadas.coordinates[0];
		let lon = position.coordenadas.coordinates[1];

		let coordenadas_doc = doc! {
			"Type" => "Point",
			"coordinates" => [lat, lon]
		};

		let entradas_ignicao = position.entradas.ignicao;
		let entradas_entrada1 = position.entradas.entrada1;
		let entradas_entrada2 = position.entradas.entrada2;
		let entradas_entrada3 = position.entradas.entrada3;
		let entradas_entrada4 = position.entradas.entrada4;
		let entradas_entrada5 = position.entradas.entrada5;
		let entradas_entrada6 = position.entradas.entrada6;
		let entradas_entrada7 = position.entradas.entrada7;

		let input_doc = doc! {
			"ignicao" => entradas_ignicao,
			"entrada1" => entradas_entrada1,
			"entrada2" => entradas_entrada2,
			"entrada3" => entradas_entrada3,
			"entrada4" => entradas_entrada4,
			"entrada5" => entradas_entrada5,
			"entrada6" => entradas_entrada6,
			"entrada7" => entradas_entrada7
		};

		let saida_saida0 = position.saidas.saida0;
		let saida_saida1 = position.saidas.saida1;
		let saida_saida2 = position.saidas.saida2;
		let saida_saida3 = position.saidas.saida3;
		let saida_saida4 = position.saidas.saida4;
		let saida_saida5 = position.saidas.saida5;
		let saida_saida6 = position.saidas.saida6;
		let saida_saida7 = position.saidas.saida7;

		let output_doc = doc! {
			"saida0" => saida_saida0,
			"saida1" => saida_saida1,
			"saida2" => saida_saida2,
			"saida3" => saida_saida3,
			"saida4" => saida_saida4,
			"saida5" => saida_saida5,
			"saida6" => saida_saida6,
			"saida7" => saida_saida7
		};

		let dado_livre_analogico1 = position.DadoLivre.Analogico1;
		let dado_livre_analogico2 = position.DadoLivre.Analogico2;
		let dado_livre_analogico3 = position.DadoLivre.Analogico3;
		let dado_livre_analogico4 = position.DadoLivre.Analogico4;
		let dado_livre_digital1 = position.DadoLivre.Digital1;
		let dado_livre_digital2 = position.DadoLivre.Digital2;
		let dado_livre_digital3 = position.DadoLivre.Digital3;
		let dado_livre_digital4 = position.DadoLivre.Digital4;
		let dado_livre_horimetro = position.DadoLivre.Horimetro;
		let dado_livre_hodometro = position.DadoLivre.Hodometro;
		let dado_livre_acelerometro_x = position.DadoLivre.AcelerometroX;
		let dado_livre_acelerometro_y = position.DadoLivre.AcelerometroY;
		let dado_livre_rpm = position.DadoLivre.Rpm;
		let dado_livre_freio = position.DadoLivre.Freio;

		let free_data = doc! {
			"Analogico1" => dado_livre_analogico1,
			"Analogico2" => dado_livre_analogico2,
			"Analogico3" => dado_livre_analogico3,
			"Analogico4" => dado_livre_analogico4,
			"Horimetro" => dado_livre_horimetro,
			"AcelerometroX" => dado_livre_acelerometro_x,
			"Digital1" => dado_livre_digital1,
			"Digital2" => dado_livre_digital2,
			"Digital3" => dado_livre_digital3,
			"Digital4" => dado_livre_digital4,
			"AcelerometroY" => dado_livre_acelerometro_y,
			"Hodometro" => dado_livre_hodometro,
			"Rpm" => dado_livre_rpm,
			"Freio" => dado_livre_freio
		};

		let id_equipamento = position.id_equipamento;
		let veiculo = position.veiculo;
		let placa = position.placa.to_string();
		let cliente = position.cliente.to_string();
		let data_posicao_str = position.data_posicao.to_string();
		let data_posicao = Bson::from(data_posicao_str.parse::<DateTime<UTC>>().ok().unwrap());
		let data_chegada = Bson::from(UTC::now());
		let endereco = position.endereco.to_string();
		let bairro = position.bairro.to_string();
		let municipio = position.municipio.to_string();
		let numero = position.numero.to_string();
		let estado = position.estado.to_string();
		let pais = position.pais.to_string();
		let velocidade_via = position.velocidade_via;
		let gps = position.gps;
		let motorista_ibutton = position.motorista_ibutton.to_string();
		let odometro_adicionado = position.odometro_adicionado;
		let horimetro_adicionado = position.horimetro_adicionado;
		let inicio_rota = position.inicio_rota;
		let fim_rota = position.fim_rota;
		let EmRe = position.EmRe;
		let tipo = position.tipo.to_string();
		let lapso = position.lapso.to_string();

		let position_doc = doc!{
			"id_equipamento" => id_equipamento,
			"veiculo" => veiculo,
			"placa" => placa,
			"cliente" => cliente,
			"data_posicao" => data_posicao,
			"data_chegada" => data_chegada,
			"endereco" => endereco,
			"bairro" => bairro,
			"municipio" => municipio,
			"numero" => numero,
			"estado" => estado,
			"coordenadas" => coordenadas_doc,
			"pais" => pais,
			"velocidade_via" => velocidade_via,
			"gps" => gps,
			"motorista_ibutton" => motorista_ibutton,
			"entradas" => input_doc,
			"saidas" => output_doc,
			"odometro_adicionado" => odometro_adicionado,
			"horimetro_adicionado" => horimetro_adicionado,
			"inicio_rota" => inicio_rota,
			"fim_rota" => fim_rota,
			"EmRe" => EmRe,
			"DadoLivre" => free_data,
			"tipo" => tipo,
			"lapso" => lapso
		};

		// Connect to the database
		let client = Client::connect("localhost", 27017)
			.ok().expect("Error establishing connection.");

		// The users collection
		let coll = client.db("rust-users").collection("posicao");

		// Insert one user
		match coll.insert_one(position_doc, None) {
			Ok(_) => (StatusCode::Ok, "Item saved!"),
			Err(e) => return response.send(format!("{}", e))
		}
	});

	router.delete("/users/:id", middleware! { |request, response|
		let client = Client::connect("localhost", 27017)
			.ok().expect("Failed to initialize standalone client.");

		// The users collection
		let coll = client.db("rust-users").collection("users");

		// Get the objectId from the request params
		let object_id = request.param("id").unwrap();

		// Match the user id to an bson ObjectId
		let id = match ObjectId::with_string(object_id) {
			Ok(oid) => oid,
			Err(e) => return response.send(format!("{}", e))
		};

		match coll.delete_one(doc! {"_id" => id}, None) {
			Ok(_) => (StatusCode::Ok, "Item deleted!"),
			Err(e) => return response.send(format!("{}", e))
		}
	});

	server.utilize(authenticator);
	server.utilize(router);
	server.listen("127.0.0.1:9000");
}
