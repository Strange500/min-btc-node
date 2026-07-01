pub const PROTOCOL_VERSION: i32 = 70015;

/// Enumerates supported Bitcoin network types.
///
/// Controls magic bytes, DNS seeds, and genesis hashes for protocol synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xF9, 0xBE, 0xB4, 0xD9],
            Network::Signet => [0x0A, 0x03, 0xCF, 0x40],
            Network::Regtest => [0xFA, 0xBF, 0xB5, 0xDA],
        }
    }

    pub fn genesis_hash(self) -> [u8; 32] {
        match self {
            Network::Mainnet => [
                0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
                0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
                0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
                0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            Network::Signet => [
                0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 
                0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9, 
                0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 
                0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
            ],
            Network::Regtest => [
                0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
                0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
                0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
                0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f
            ],
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    pub fn dns_seeds(self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &[
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
            ],
            Network::Signet => &[
                "seed.signet.bitcoin.sprovoost.nl",
            ],
            Network::Regtest => &["127.0.0.1"],
        }
    }
}
