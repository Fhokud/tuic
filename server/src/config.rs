use crate::certificate;
use getopts::{Fail, Options};
use log::{LevelFilter, ParseLevelError};
use quinn::{
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    IdleTimeout, ServerConfig, TransportConfig, VarInt,
};
use rustls::Error as RustlsError;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use serde_json::Error as JsonError;
use std::{
    env::ArgsOs, fmt::Display, fs::File, io::Error as IoError, num::ParseIntError, str::FromStr,
    sync::Arc, time::Duration,
};
use thiserror::Error;

pub struct Config {
    pub server_config: ServerConfig,
    pub port: u16,
    pub token_digest: [u8; 32],
    pub authentication_timeout: Duration,
    pub max_udp_packet_size: usize,
    pub enable_ipv6: bool,
    pub log_level: LevelFilter,
}

impl Config {
    pub fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
        let raw = RawConfig::parse(args)?;

        let server_config = {
            let cert_path = raw.certificate.unwrap();
            let certs = certificate::load_certificates(&cert_path)
                .map_err(|err| ConfigError::Io(cert_path, err))?;

            let priv_key_path = raw.private_key.unwrap();
            let priv_key = certificate::load_private_key(&priv_key_path)
                .map_err(|err| ConfigError::Io(priv_key_path, err))?;

            let mut config = ServerConfig::with_single_cert(certs, priv_key)?;
            let mut transport = TransportConfig::default();

            match raw.congestion_controller {
                CongestionController::Bbr => {
                    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
                }
                CongestionController::Cubic => {
                    transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
                }
                CongestionController::NewReno => {
                    transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
                }
            }

            transport
                .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(raw.max_idle_time))));

            config.transport = Arc::new(transport);
            config
        };

        let port = raw.port.unwrap();
        let token_digest = *blake3::hash(&raw.token.unwrap().into_bytes()).as_bytes();
        let authentication_timeout = Duration::from_secs(raw.authentication_timeout);
        let max_udp_packet_size = raw.max_udp_packet_size;
        let enable_ipv6 = raw.enable_ipv6;
        let log_level = raw.log_level;

        Ok(Self {
            server_config,
            port,
            token_digest,
            authentication_timeout,
            max_udp_packet_size,
            enable_ipv6,
            log_level,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    port: Option<u16>,
    token: Option<String>,
    certificate: Option<String>,
    private_key: Option<String>,

    #[serde(
        default = "default::congestion_controller",
        deserialize_with = "deserialize_from_str"
    )]
    congestion_controller: CongestionController,

    #[serde(default = "default::max_idle_time")]
    max_idle_time: u32,

    #[serde(default = "default::authentication_timeout")]
    authentication_timeout: u64,

    #[serde(default = "default::max_udp_packet_size")]
    max_udp_packet_size: usize,

    #[serde(default = "default::enable_ipv6")]
    enable_ipv6: bool,

    #[serde(default = "default::log_level")]
    log_level: LevelFilter,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            port: None,
            token: None,
            certificate: None,
            private_key: None,
            congestion_controller: default::congestion_controller(),
            max_idle_time: default::max_idle_time(),
            authentication_timeout: default::authentication_timeout(),
            max_udp_packet_size: default::max_udp_packet_size(),
            enable_ipv6: default::enable_ipv6(),
            log_level: default::log_level(),
        }
    }
}

impl RawConfig {
    fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
        let mut opts = Options::new();

        opts.optopt(
            "c",
            "config",
            "Read configuration from a file. Note that command line arguments will override the configuration file",
            "CONFIG_FILE",
        );

        opts.optopt("", "port", "Set the server listening port", "SERVER_PORT");

        opts.optopt(
            "",
            "token",
            "Set the token for TUIC authentication",
            "TOKEN",
        );

        opts.optopt(
            "",
            "certificate",
            "Set the X.509 certificate. This must be an end-entity certificate",
            "CERTIFICATE",
        );

        opts.optopt(
            "",
            "private-key",
            "Set the certificate private key",
            "PRIVATE_KEY",
        );

        opts.optopt(
            "",
            "congestion-controller",
            r#"Set the congestion control algorithm. Available: "cubic", "new_reno", "bbr". Default: "cubic""#,
            "CONGESTION_CONTROLLER",
        );

        opts.optopt(
            "",
            "max-idle-time",
            "Set the maximum idle time for connections, in milliseconds. The true idle timeout is the minimum of this and the client's one. Default: 15000",
            "MAX_IDLE_TIME",
        );

        opts.optopt(
            "",
            "authentication-timeout",
            "Set the maximum time allowed between a QUIC connection established and the TUIC authentication packet received, in milliseconds. Default: 1000",
            "AUTHENTICATION_TIMEOUT",
        );

        opts.optopt(
            "",
            "max-udp-packet-size",
            "Set the maximum UDP packet size, in bytes. Excess bytes may be discarded. Default: 1536",
            "MAX_UDP_PACKET_SIZE",
        );

        opts.optflag("", "enable-ipv6", "Enable IPv6 support");

        opts.optopt(
            "",
            "log-level",
            r#"Set the log level. Available: "off", "error", "warn", "info", "debug", "trace". Default: "info""#,
            "LOG_LEVEL",
        );

        opts.optflag("v", "version", "Print the version");
        opts.optflag("h", "help", "Print this help menu");

        let matches = opts.parse(args.skip(1))?;

        if matches.opt_present("help") {
            return Err(ConfigError::Help(opts.usage(env!("CARGO_PKG_NAME"))));
        }

        if matches.opt_present("version") {
            return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
        }

        if !matches.free.is_empty() {
            return Err(ConfigError::UnexpectedArguments(matches.free.join(", ")));
        }

        let port = matches.opt_str("port").map(|port| port.parse());
        let token = matches.opt_str("token");
        let certificate = matches.opt_str("certificate");
        let private_key = matches.opt_str("private-key");

        let mut raw = if let Some(path) = matches.opt_str("config") {
            let mut raw = RawConfig::from_file(path)?;

            raw.port = Some(
                port.transpose()?
                    .or(raw.port)
                    .ok_or(ConfigError::MissingOption("port"))?,
            );

            raw.token = Some(
                token
                    .or(raw.token)
                    .ok_or(ConfigError::MissingOption("token"))?,
            );

            raw.certificate = Some(
                certificate
                    .or(raw.certificate)
                    .ok_or(ConfigError::MissingOption("certificate"))?,
            );

            raw.private_key = Some(
                private_key
                    .or(raw.private_key)
                    .ok_or(ConfigError::MissingOption("private key"))?,
            );

            raw
        } else {
            RawConfig {
                port: Some(port.ok_or(ConfigError::MissingOption("port"))??),
                token: Some(token.ok_or(ConfigError::MissingOption("token"))?),
                certificate: Some(certificate.ok_or(ConfigError::MissingOption("certificate"))?),
                private_key: Some(private_key.ok_or(ConfigError::MissingOption("private key"))?),
                ..Default::default()
            }
        };

        if let Some(cgstn_ctrl) = matches.opt_str("congestion-controller") {
            raw.congestion_controller = cgstn_ctrl.parse()?;
        };

        if let Some(timeout) = matches.opt_str("max-idle-time") {
            raw.max_idle_time = timeout.parse()?;
        };

        if let Some(timeout) = matches.opt_str("authentication-timeout") {
            raw.authentication_timeout = timeout.parse()?;
        };

        if let Some(max_udp_packet_size) = matches.opt_str("max-udp-packet-size") {
            raw.max_udp_packet_size = max_udp_packet_size.parse()?;
        };

        raw.enable_ipv6 |= matches.opt_present("enable-ipv6");

        if let Some(log_level) = matches.opt_str("log-level") {
            raw.log_level = log_level.parse()?;
        };

        Ok(raw)
    }

    fn from_file(path: String) -> Result<Self, ConfigError> {
        let file = File::open(&path).map_err(|err| ConfigError::Io(path, err))?;
        let raw = serde_json::from_reader(file)?;
        Ok(raw)
    }
}

enum CongestionController {
    Cubic,
    NewReno,
    Bbr,
}

impl FromStr for CongestionController {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(CongestionController::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(CongestionController::NewReno)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(CongestionController::Bbr)
        } else {
            Err(ConfigError::InvalidCongestionController)
        }
    }
}

fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(DeError::custom)
}

mod default {
    use super::*;

    pub(super) const fn congestion_controller() -> CongestionController {
        CongestionController::Cubic
    }

    pub(super) const fn max_idle_time() -> u32 {
        15000
    }

    pub(super) const fn authentication_timeout() -> u64 {
        1000
    }

    pub(super) const fn max_udp_packet_size() -> usize {
        1536
    }

    pub(super) const fn enable_ipv6() -> bool {
        false
    }

    pub(super) const fn log_level() -> LevelFilter {
        LevelFilter::Info
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Help(String),
    #[error("{0}")]
    Version(&'static str),
    #[error("Failed to read '{0}': {1}")]
    Io(String, #[source] IoError),
    #[error("Failed to parse the config file: {0}")]
    ParseConfigJson(#[from] JsonError),
    #[error(transparent)]
    ParseArgument(#[from] Fail),
    #[error("Unexpected arguments: {0}")]
    UnexpectedArguments(String),
    #[error("Missing option: {0}")]
    MissingOption(&'static str),
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),
    #[error("Invalid congestion controller")]
    InvalidCongestionController,
    #[error(transparent)]
    ParseLogLevel(#[from] ParseLevelError),
    #[error("Failed to load certificate / private key: {0}")]
    Rustls(#[from] RustlsError),
}
