#[derive(RustcDecodable, RustcEncodable)]
pub struct UserLogin {
	pub email: String,
	pub password: String
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct User {
	pub firstname: String,
	pub lastname: String,
	pub email: String
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct PositionCoordinates {
	pub Type: String,
	pub coordinates: [f64; 2]
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct PositionInput {
	pub ignicao: bool,
	pub entrada1: bool,
	pub entrada2: bool,
	pub entrada3: bool,
	pub entrada4: bool,
	pub entrada5: bool,
	pub entrada6: bool,
	pub entrada7: bool
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct PositionOutput {
	pub saida0: bool,
	pub saida1: bool,
	pub saida2: bool,
	pub saida3: bool,
	pub saida4: bool,
	pub saida5: bool,
	pub saida6: bool,
	pub saida7: bool
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct PositionFreeData {
	pub Analogico1: bool,
	pub Analogico2: bool,
	pub Analogico3: bool,
	pub Analogico4: bool,
	pub Horimetro: f32,
	pub AcelerometroX: f32,
	pub Digital1: bool,
	pub Digital2: bool,
	pub Digital3: bool,
	pub Digital4: bool,
	pub AcelerometroY: f32,
	pub Hodometro: f32,
	pub Rpm: u32,
	pub Freio: bool
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct Position {
	pub id_equipamento: u32,
	pub veiculo: u32,
	pub placa: String,
	pub cliente: String,
	pub data_posicao: String,
	pub data_chegada: String,
	pub endereco: String,
	pub bairro: String,
	pub municipio: String,
	pub numero: String,
	pub estado: String,
	pub coordenadas: PositionCoordinates,
	pub pais: String,
	pub velocidade_via: u32,
	pub gps: bool,
	pub motorista_ibutton: String,
	pub entradas: PositionInput,
	pub saidas: PositionOutput,
	pub odometro_adicionado: bool,
	pub horimetro_adicionado: bool,
	pub inicio_rota: bool,
	pub fim_rota: bool,
	pub EmRe: bool,
	pub DadoLivre: PositionFreeData,
	pub tipo: String,
	pub lapso: String
}