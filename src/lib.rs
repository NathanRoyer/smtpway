use futures_rustls::TlsAcceptor;
use async_net::TcpStream;
use rustls::ServerConfig;
use std::str::from_utf8;
use std::mem::replace;
use std::net::IpAddr;
use std::fmt::Write;
use std::sync::Arc;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

type TlsStream = futures_rustls::server::TlsStream<TcpStream>;

const BUF_UNIT: usize = 0x10000;
const BAD_CMD: &str = "502 Command not implemented\r\n";
const SRV_HELO: &str = "Hello friend!";

#[derive(Copy, Clone, PartialEq, Debug)]
enum Error {
    Disconnected,
    TlsError,
    AlreadyTls,
    NoPeerAddr,
    BrokenPipe,
    AsciiViolation,
}

macro_rules! conn_write {
    ($this:expr, $($arg:tt)*) => {{
        $this.out_buf.clear();
        _ = write!(&mut $this.out_buf, $($arg)*);
        match &mut $this.stream {
            Stream::Tls(tls) => _ = tls.write_all($this.out_buf.as_bytes()).await,
            Stream::Tcp(tcp) => _ = tcp.write_all($this.out_buf.as_bytes()).await,
            Stream::None => unreachable!(),
        }
    }};
}

enum Stream {
    Tls(TlsStream),
    Tcp(TcpStream),
    None,
}

pub struct Email<'a> {
    pub peer_ip: IpAddr,
    pub recipients: &'a [String],
    pub sender: &'a str,
    pub data: String,
    pub tls: bool,
}

#[allow(async_fn_in_trait)]
pub trait Handler {
    async fn valid_recipient(&self, _recipient: &str) -> bool { true }
    async fn got_mail(&self, email: &Email);
}

struct SmtpServer<H: Handler> {
    tls_acceptor: TlsAcceptor,
    hostname: String,
    stream: Stream,
    handler: H,

    // current email
    recipients: Vec<String>,
    sender: Option<String>,

    // buffers:
    out_buf: String,
    in_line: String,
    in_buf: Vec<u8>,
}

impl<H: Handler> SmtpServer<H> {
    async fn run(&mut self) -> Result<(), Error> {
        // greet client
        conn_write!(self, "220 {} smtpway\r\n", self.hostname);

        loop {
            self.read_line().await?;

            match self.in_line.as_str() {
                "STARTTLS" => {
                    conn_write!(self, "220 Ready to start TLS\r\n");
                    self.upgrade().await?;
                },
                _other => self.handle_cmd().await?,
            }
        }
    }

    async fn upgrade(&mut self) -> Result<(), Error> {
        let stream = replace(&mut self.stream, Stream::None);

        let Stream::Tcp(tcp_stream) = stream else {
            return Err(Error::AlreadyTls);
        };

        let Ok(tls_stream) = self.tls_acceptor.accept(tcp_stream).await else {
            return Err(Error::TlsError);
        };

        self.stream = Stream::Tls(tls_stream);
        Ok(())
    }

    async fn handle_cmd(&mut self) -> Result<(), Error> {
        // println!("(command: {})", self.in_line);

        let mut parts = self.in_line.split_whitespace();
        let command = parts.next().unwrap_or("");
        let argument = parts.next().unwrap_or("");
        let is_cmd = |candidate: &str| candidate.eq_ignore_ascii_case(command);

        let arg_extract = |expected_kw: &str| {
            let (before, after) = argument.split_once(":<")?;
            match before.eq_ignore_ascii_case(expected_kw) {
                true => after.strip_suffix('>'),
                false => None,
            }
        };

        match () {
            _ if is_cmd("HELO") => {
                conn_write!(self, "250 {} {}\r\n", self.hostname, SRV_HELO);
            }

            _ if is_cmd("EHLO") => {
                conn_write!(self, "250-{} {}\r\n", self.hostname, SRV_HELO);
                // conn_write!(self, "250-8BITMIME\r\n");
                conn_write!(self, "250 STARTTLS\r\n");
            }

            _ if is_cmd("MAIL") => {
                let status = if let Some(sender) = arg_extract("from") {
                    self.sender = Some(sender.to_string());
                    "250 OK\r\n"
                } else {
                    "501 Invalid Sender\r\n"
                };

                conn_write!(self, "{}", status);
            }

            _ if is_cmd("RCPT") => {
                let mut valid_rcpt = false;

                if let Some(recipient) = arg_extract("to") {
                    let recipient = recipient.to_string();

                    valid_rcpt = !self.recipients.contains(&recipient)
                              && self.handler.valid_recipient(&recipient).await;

                    if valid_rcpt {
                        self.recipients.push(recipient);
                    }
                };

                let status = match valid_rcpt {
                    true => "250 OK\r\n",
                    false => "501 Invalid Recipient\r\n",
                };

                conn_write!(self, "{}", status);
            }

            _ if is_cmd("DATA") => self.handle_data().await?,

            _ if is_cmd("RSET") => {
                self.sender = None;
                self.recipients.clear();
                conn_write!(self, "250 OK\r\n");
            }

            _ if is_cmd("QUIT") => conn_write!(self, "221 Bye\r\n"),
            _ => conn_write!(self, "{}", BAD_CMD),
        }

        Ok(())
    }

    async fn handle_data(&mut self) -> Result<(), Error> {
        if self.recipients.is_empty() | self.sender.is_none() {
            conn_write!(self, "503 No sender/recipients");
            return Ok(());
        }

        conn_write!(self, "354 Ready to receive data.\r\n");
        let mut data = String::new();

        loop {
            self.read_line().await?;

            let line = match self.in_line.strip_prefix('.') {
                Some("") => break,
                Some(escaped) => escaped,
                _ => &self.in_line,
            };

            data += line;
            data += "\r\n";
        }

        conn_write!(self, "250 Message Accepted\r\n");

        let (tcp_stream, tls) = match &self.stream {
            Stream::Tcp(tcp_stream) => (tcp_stream, false),
            Stream::Tls(tls) => (tls.get_ref().0, true),
            Stream::None => unreachable!(),
        };

        let Ok(client_addr) = tcp_stream.peer_addr() else {
            return Err(Error::NoPeerAddr);
        };

        let email = Email {
            sender: self.sender.as_ref().unwrap(),
            recipients: &self.recipients,
            peer_ip: client_addr.ip(),
            data,
            tls,
        };

        self.handler.got_mail(&email).await;

        // todo: maybe clear from/rcpt buffers
        Ok(())
    }

    async fn read_until(&mut self, delim: &[u8]) -> Result<usize, Error> {
        loop {
            if let Some(i) = self.in_buf.windows(2).position(|slice| slice == delim) {
                break Ok(i);
            }

            let prev_len = self.in_buf.len();
            self.in_buf.resize(prev_len + BUF_UNIT, 0);
            let new_space = &mut self.in_buf[prev_len..];

            let res = match &mut self.stream {
                Stream::Tls(s) => s.read(new_space).await,
                Stream::Tcp(s) => s.read(new_space).await,
                Stream::None => unreachable!(),
            };

            let Ok(received) = res else {
                break Err(Error::BrokenPipe);
            };

            if received == 0 {
                break Err(Error::Disconnected);
            }

            self.in_buf.truncate(prev_len + received);
        }
    }

    async fn read_line(&mut self) -> Result<(), Error> {
        let delim = b"\r\n";
        let delim_start = self.read_until(delim).await?;
        let line_bytes = &self.in_buf[..delim_start];

        let Ok(line) = from_utf8(line_bytes) else {
            return Err(Error::AsciiViolation);
        };

        self.in_line.replace_range(.., line);

        let to_drain = delim_start + delim.len();
        self.in_buf.drain(..to_drain);

        Ok(())
    }
}

pub async fn session<H: Handler>(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    hostname: String,
    handler: H,
    smtps: bool,
) {
    let mut server = SmtpServer {
        tls_acceptor: TlsAcceptor::from(tls_config),
        stream: Stream::Tcp(stream),
        hostname,
        handler,

        recipients: Vec::new(),
        sender: None,

        out_buf: String::new(),
        in_line: String::new(),
        in_buf: Vec::new(),
    };

    if smtps {
        if let Err(error) = server.upgrade().await {
            println!("smtps error: {error:?}");
        }
    }

    let Err(error) = server.run().await else {
        unreachable!();
    };

    if error != Error::Disconnected {
        println!("error: {error:?}");
    }
}
