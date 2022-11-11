use crate::blockstore::Blockstore;
use anyhow::Result;
use async_trait::async_trait;
use futures::io::copy;
use integer_encoding::{VarIntReader, VarIntWriter};
use libipld::cid::multihash::{Code, Error as MultihashError, Multihash, MultihashDigest};
use libipld::cid::{Error as CidError, Version};
use libipld::codec::{Codec, Decode, Encode};
use libipld::codec_impl::IpldCodec;
use libipld::error::{Error as IpldError, UnsupportedCodec};
use libipld::{Cid, Ipld};
use std::io::{Cursor, Error as IoError};
use thiserror::Error;

#[derive(Clone)]
pub struct LinkSystem<BS> {
    bstore: BS,
}

#[derive(Error, Debug)]
pub enum LinkError<S> {
    #[error(transparent)]
    Store(S),
    #[error(transparent)]
    Prefix(#[from] PrefixError),
    #[error(transparent)]
    Ipld(#[from] IpldError),
    #[error(transparent)]
    Codec(#[from] UnsupportedCodec),
    #[error("Not Found: {0}")]
    NotFound(Cid),
    #[error(transparent)]
    Io(#[from] IoError),
}

impl<BS> LinkSystem<BS>
where
    BS: Blockstore,
{
    pub fn new(bstore: BS) -> Self {
        Self { bstore }
    }
    pub async fn store(&self, p: Prefix, n: &Ipld) -> Result<Cid, LinkError<BS::Error>> {
        let codec = IpldCodec::try_from(p.codec)?;
        let mut buf = Vec::new();
        Ipld::encode(n, codec, &mut buf)?;
        let cid = p.to_cid(&buf)?;
        self.bstore
            .put_keyed(&cid, buf.as_ref() as &[u8])
            .await
            .map_err(LinkError::Store)?;
        Ok(cid)
    }
    pub async fn store_plus_raw(
        &self,
        p: Prefix,
        n: &Ipld,
    ) -> Result<(Cid, Vec<u8>), LinkError<BS::Error>> {
        let codec = IpldCodec::try_from(p.codec)?;
        let mut buf = Vec::new();
        Ipld::encode(n, codec, &mut buf)?;
        let cid = p.to_cid(&buf)?;
        self.bstore
            .put_keyed(&cid, buf.as_ref() as &[u8])
            .await
            .map_err(LinkError::Store)?;
        Ok((cid, buf))
    }
    pub async fn compute_link(&self, p: Prefix, n: &Ipld) -> Result<Cid, LinkError<BS::Error>> {
        let codec = IpldCodec::try_from(p.codec)?;
        let mut buf = Vec::new();
        Ipld::encode(n, codec, &mut buf)?;
        let cid = p.to_cid(&buf)?;
        Ok(cid)
    }
}

#[async_trait]
pub trait BlockLoader {
    type Error;
    async fn load_plus_raw(&self, cid: Cid) -> Result<(Ipld, Vec<u8>), Self::Error>;
}

#[async_trait]
impl<BS> BlockLoader for LinkSystem<BS>
where
    BS: Blockstore + Send + Sync,
    BS::BlockData: Send,
    BS::Error: Send,
{
    type Error = LinkError<BS::Error>;
    async fn load_plus_raw(&self, cid: Cid) -> Result<(Ipld, Vec<u8>), Self::Error> {
        if let Some(blk) = self.bstore.get(&cid).await.map_err(LinkError::Store)? {
            let codec = IpldCodec::try_from(cid.codec())?;
            let mut buffer: Vec<u8> = Vec::new();
            copy(blk, &mut buffer).await?;
            let node = codec.decode(&buffer)?;
            return Ok((node, buffer));
        }
        Err(LinkError::NotFound(cid))
    }
}

#[async_trait]
pub trait IpldLoader {
    async fn load(&self, cid: Cid) -> Result<Ipld, LoaderError>;
}

#[async_trait]
impl<BS> IpldLoader for LinkSystem<BS>
where
    BS: Blockstore + Send + Sync,
    BS::BlockData: Send,
    BS::Error: std::fmt::Display + Send,
{
    async fn load(&self, cid: Cid) -> Result<Ipld, LoaderError> {
        let codec =
            IpldCodec::try_from(cid.codec()).map_err(|e| LoaderError::Codec(e.to_string()))?;
        if let Some(blk) = self
            .bstore
            .get(&cid)
            .await
            .map_err(|e| LoaderError::Blockstore(e.to_string()))?
        {
            let mut buffer: Vec<u8> = Vec::new();
            copy(blk, &mut buffer)
                .await
                .map_err(|e| LoaderError::Decoding(e.to_string()))?;
            let mut reader = Cursor::new(buffer);
            return Ipld::decode(codec, &mut reader)
                .map_err(|e| LoaderError::Decoding(e.to_string()).into());
        }
        Err(LoaderError::NotFound(cid).into())
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum LoaderError {
    #[error("block not found for {0}")]
    NotFound(Cid),
    #[error("skip block for {0}")]
    SkipMe(Cid),
    #[error("failed to decode: {0}")]
    Decoding(String),
    #[error("invalid multicodec: {0}")]
    Codec(String),
    #[error("blockstore: {0}")]
    Blockstore(String),
}

/// Represents a CID Prefix.
///
/// A CID Prefix consists of a version (defaults to 1), a codec id,
/// an optional multihash length and id.
///
/// # Examples
///
/// Creating a prefix straight from known ids.
///
/// ```
/// use ipld_traversal::Prefix;
///
/// // Raw bytes codec and SHA256 multihash.
/// let prefix = Prefix::new(0x55, 0x12);
/// ```
///
/// Creating a prefix with the builder pattern.
///
/// ```
/// use ipld_traversal::Prefix;
///
/// let prefix = Prefix::builder()
///     .raw()
///     .sha256()
///     .build();
/// ```
///
/// Or creating a prefix with libipld enums.
/// ```
/// use libipld::cbor::DagCborCodec;
/// use libipld::multihash::Code;
/// use ipld_traversal::Prefix;
///
/// let prefix = Prefix::new(DagCborCodec.into(), Code::Sha2_256.into());
///
/// ```
///
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct Prefix {
    pub version: Version,
    pub codec: u64,
    pub mh_type: u64,
    pub mh_len: usize,
}

#[derive(Error, Debug)]
pub enum PrefixError {
    #[error(transparent)]
    Multihash(#[from] MultihashError),
    #[error(transparent)]
    Cid(#[from] CidError),
}

impl Prefix {
    // default to cid v1 with default hash length
    pub fn new(codec: u64, mh_type: u64) -> Self {
        Prefix {
            version: Version::V1,
            codec,
            mh_type,
            mh_len: 0,
        }
    }

    #[inline]
    pub fn builder() -> Builder {
        Builder::new()
    }

    pub fn new_from_bytes(data: &[u8]) -> Result<Prefix> {
        let mut cur = Cursor::new(data);

        let raw_version: u64 = cur.read_varint()?;
        let codec = cur.read_varint()?;
        let mh_type: u64 = cur.read_varint()?;
        let mh_len: usize = cur.read_varint()?;

        let version = Version::try_from(raw_version)?;

        Ok(Prefix {
            version,
            codec,
            mh_type,
            mh_len,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(4);

        res.write_varint(u64::from(self.version)).unwrap();
        res.write_varint(self.codec).unwrap();
        res.write_varint(self.mh_type).unwrap();
        res.write_varint(self.mh_len).unwrap();

        res
    }

    pub fn to_cid(&self, data: &[u8]) -> Result<Cid, PrefixError> {
        let hash: Multihash = Code::try_from(self.mh_type)?.digest(data);
        let cid = Cid::new(self.version, self.codec, hash)?;
        Ok(cid)
    }
}

impl From<Cid> for Prefix {
    fn from(cid: Cid) -> Self {
        Self {
            version: cid.version(),
            codec: cid.codec(),
            mh_type: cid.hash().code(),
            mh_len: cid.hash().size().into(),
        }
    }
}

/// A Prefix builder
///
/// This type provides some commonly used codecs and multihashes
/// to quickly build a prefix.
#[derive(Debug)]
pub struct Builder {
    inner: Prefix,
}

impl Default for Builder {
    #[inline]
    fn default() -> Builder {
        Builder {
            inner: Prefix::new(0, 0),
        }
    }
}

impl Builder {
    #[inline]
    pub fn new() -> Builder {
        Builder::default()
    }

    #[inline]
    pub fn dag_cbor(mut self) -> Builder {
        self.inner.codec = 0x71;
        self
    }

    #[inline]
    pub fn dag_pb(mut self) -> Builder {
        self.inner.codec = 0x70;
        self
    }

    #[inline]
    pub fn dag_json(mut self) -> Builder {
        self.inner.codec = 0x0129;
        self
    }

    #[inline]
    pub fn raw(mut self) -> Builder {
        self.inner.codec = 0x55;
        self
    }

    #[inline]
    pub fn sha256(mut self) -> Builder {
        self.inner.mh_type = 0x12;
        self
    }

    #[inline]
    pub fn sha512(mut self) -> Builder {
        self.inner.mh_type = 0x13;
        self
    }

    pub fn build(self) -> Prefix {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::MemoryBlockstore;
    use libipld::ipld;

    // same test as go-ipld-prime
    #[async_std::test]
    async fn setup_from_blockstore() {
        let store = MemoryBlockstore::new();
        let lsys = LinkSystem::new(store);

        let value = ipld!({
            "hello": "world",
        });
        lsys.store(
            Prefix::new(
                0x71, // dag-cbor
                0x13, // sha-512
            ),
            &value,
        )
        .await
        .unwrap();
        let key: Cid = "bafyrgqhai26anf3i7pips7q22coa4sz2fr4gk4q4sqdtymvvjyginfzaqewveaeqdh524nsktaq43j65v22xxrybrtertmcfxufdam3da3hbk".parse().unwrap();
        let n = lsys.load(key).await.unwrap();
        assert_eq!(n, value);
    }
}
