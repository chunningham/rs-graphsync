use async_trait::async_trait;
use futures::io::{copy, AsyncRead, Cursor};
use libipld::{
    cid::multihash::{self, Multihash, MultihashDigest},
    Cid,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

// Same block/blockstore implementation as the fvm.
// Will import from there once it gets published separately.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Block<D>
where
    D: AsyncRead + ?Sized,
{
    pub codec: u64,
    pub data: D,
}

impl<D> Block<D>
where
    D: AsyncRead + ?Sized,
{
    pub fn new(codec: u64, data: D) -> Self
    where
        Self: Sized,
        D: Sized,
    {
        Self { codec, data }
    }
}

/// An IPLD blockstore suitable for injection into the FVM.
///
/// The cgo blockstore adapter implements this trait.
#[async_trait]
pub trait Blockstore {
    type BlockData: AsyncRead;
    type Error;
    /// Gets the block from the blockstore.
    async fn get(&self, k: &Cid) -> Result<Option<Self::BlockData>, Self::Error>;

    /// Put a block with a pre-computed cid.
    ///
    /// If you don't yet know the CID, use put. Some blockstores will re-compute the CID internally
    /// even if you provide it.
    ///
    /// If you _do_ already know the CID, use this method as some blockstores _won't_ recompute it.
    async fn put_keyed(&self, k: &Cid, block: impl AsyncRead + Send) -> Result<(), Self::Error>;

    /// Checks if the blockstore has the specified block.
    async fn has(&self, k: &Cid) -> Result<bool, Self::Error> {
        Ok(self.get(k).await?.is_some())
    }

    /// Puts the block into the blockstore, computing the hash with the specified multicodec.
    ///
    /// By default, this defers to put.
    async fn put<D>(&self, mh_code: multihash::Code, block: Block<D>) -> Result<Cid, Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send;

    /// Bulk put blocks into the blockstore.
    async fn put_many<D, I>(&self, blocks: I) -> Result<(), Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send,
        I: IntoIterator<Item = (multihash::Code, Block<D>)> + Send,
        I::IntoIter: Send,
    {
        for (c, b) in blocks {
            self.put(c, b).await?;
        }
        Ok(())
    }

    /// Bulk-put pre-keyed blocks into the blockstore.
    ///
    /// By default, this defers to put_keyed.
    async fn put_many_keyed<D, I>(&self, blocks: I) -> Result<(), Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send,
        I: IntoIterator<Item = (Cid, D)> + Send,
        I::IntoIter: Send,
    {
        for (c, b) in blocks {
            self.put_keyed(&c, b).await?
        }
        Ok(())
    }

    /// Deletes the block for the given Cid key.
    async fn delete_block(&self, k: &Cid) -> Result<(), Self::Error>;
}

#[async_trait]
impl<BS> Blockstore for &BS
where
    BS: Blockstore + Sync,
{
    type BlockData = BS::BlockData;
    type Error = BS::Error;
    async fn get(&self, k: &Cid) -> Result<Option<Self::BlockData>, Self::Error> {
        (*self).get(k).await
    }

    async fn put_keyed(&self, k: &Cid, block: impl AsyncRead + Send) -> Result<(), Self::Error> {
        (*self).put_keyed(k, block).await
    }

    async fn has(&self, k: &Cid) -> Result<bool, Self::Error> {
        (*self).has(k).await
    }

    async fn delete_block(&self, k: &Cid) -> Result<(), Self::Error> {
        (*self).delete_block(k).await
    }

    async fn put<D>(&self, mh_code: multihash::Code, block: Block<D>) -> Result<Cid, Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send,
    {
        (*self).put(mh_code, block).await
    }

    async fn put_many<D, I>(&self, blocks: I) -> Result<(), Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send,
        I: IntoIterator<Item = (multihash::Code, Block<D>)> + Send,
        I::IntoIter: Send,
    {
        (*self).put_many(blocks).await
    }

    async fn put_many_keyed<D, I>(&self, blocks: I) -> Result<(), Self::Error>
    where
        Self: Sized,
        D: AsyncRead + Send,
        I: IntoIterator<Item = (Cid, D)> + Send,
        I::IntoIter: Send,
    {
        (*self).put_many_keyed(blocks).await
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryBlockstore {
    blocks: Arc<Mutex<HashMap<Cid, Vec<u8>>>>,
}

impl MemoryBlockstore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MemStoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Content Mismatch")]
    ContentMismatch(Multihash),
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
}

#[async_trait]
impl Blockstore for MemoryBlockstore {
    type BlockData = Cursor<Vec<u8>>;
    type Error = MemStoreError;
    async fn has(&self, k: &Cid) -> Result<bool, Self::Error> {
        Ok(self.blocks.lock().unwrap().contains_key(k))
    }

    async fn get(&self, k: &Cid) -> Result<Option<Self::BlockData>, Self::Error> {
        Ok(self.blocks.lock().unwrap().get(k).cloned().map(Cursor::new))
    }

    async fn put<D>(&self, mh_code: multihash::Code, block: Block<D>) -> Result<Cid, Self::Error>
    where
        D: AsyncRead + Send,
    {
        let mut buffer: Vec<u8> = Vec::new();
        copy(block.data, &mut buffer).await?;
        let hash = mh_code.digest(&buffer);
        let cid = Cid::new_v1(block.codec, hash);
        self.blocks.lock().unwrap().insert(cid.clone(), buffer);
        Ok(cid)
    }

    async fn put_keyed(&self, k: &Cid, block: impl AsyncRead + Send) -> Result<(), Self::Error> {
        let mut buffer: Vec<u8> = Vec::new();
        copy(block, &mut buffer).await?;
        let code: multihash::Code = k.hash().code().try_into()?;
        let hash = code.digest(&buffer);
        if hash != *k.hash() {
            return Err(MemStoreError::ContentMismatch(hash));
        }

        self.blocks.lock().unwrap().insert(*k, buffer);
        Ok(())
    }

    async fn delete_block(&self, k: &Cid) -> Result<(), Self::Error> {
        self.blocks.lock().unwrap().remove(k);
        Ok(())
    }
}
