use futures_lite::prelude::*;
use async_net::TcpListener;
use async_exec::Executor;
use rustls::ServerConfig;
use std::sync::Arc;
use smtpway::*;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::pki_types::pem::PemObject;

const CERT: CertificateDer = CertificateDer::from_slice(include_bytes!("cert.der"));
const PKEY: &[u8] = include_bytes!("pkey.pem");

struct LoggingHandler;

impl Handler for LoggingHandler {
    async fn got_mail(&self, email: &Email<'_>) {
        let rcpts = email.recipients.join(", ");
        println!("[ip={} from={} to={}] {}", email.peer_ip, email.sender, rcpts, email.data);
    }
}

async fn run(exec: Arc<Executor>, tls_config: Arc<ServerConfig>, port: u16) {
    let addr = ("0.0.0.0", port);
    let listener = TcpListener::bind(addr).await.unwrap();
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let stream = stream.unwrap();
        let tls_config = tls_config.clone();
        let hostname = "localhost".to_string();

        let new_task = session(stream, tls_config, hostname, LoggingHandler);

        exec.spawn(new_task);
    }
}

fn main() {
    let exec = Arc::new(Executor::new(4, None));

    let pkey = PrivateKeyDer::from_pem_slice(PKEY).unwrap();

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CERT], pkey)
        .unwrap();

    let tls_config = Arc::new(tls_config);

    let srv_25 = run(exec.clone(), tls_config.clone(), 25);
    let srv_587 = run(exec.clone(), tls_config.clone(), 587);

    exec.spawn(srv_25);
    exec.spawn(srv_587);

    let _ = Executor::join_arc(exec);
}