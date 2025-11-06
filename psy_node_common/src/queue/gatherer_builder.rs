use async_trait::async_trait;
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsySerializeCanonicalAsyncSafe};
use tokio::io::AsyncWriteExt;
use tokio::try_join;
#[async_trait]
pub trait QueueGathererItemBuilder<C>: Sized {
    type Output: Sized + Send + Sync;
    async fn create_new(unique_id: u128, config: C) -> anyhow::Result<Self>;
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()>;
    async fn update_from_many_queue_items(&mut self, item: Vec<Vec<u8>>) -> anyhow::Result<()> {
        for it in item {
            self.update_from_queue_item(it).await?;
        }
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output>;
}

#[async_trait]
pub trait QueueGathererItemBuilderWithTree<C, Tree>: Sized {
    type Output: Sized + Send + Sync;
    async fn create_new_with_tree(tree: &mut Tree, unique_id: u128, config: C) -> anyhow::Result<Self>;
    async fn update_from_queue_item_with_tree(&mut self, tree: &mut Tree, item: Vec<u8>) -> anyhow::Result<()>;
    async fn update_from_many_queue_items_with_tree(&mut self, tree: &mut Tree, item: Vec<Vec<u8>>) -> anyhow::Result<()>;
    async fn finalize_with_tree(self, tree: &mut Tree) -> anyhow::Result<Self::Output>;
}


#[async_trait]
pub trait QueueGathererItemBuilderWithTreeRef<C, Tree>: Sized {
    type Output: Sized + Send + Sync;
    async fn create_new_with_tree_ref(tree: &mut Tree, unique_id: u128, config: C) -> anyhow::Result<Self>;
    async fn update_from_queue_item_with_tree_ref(&mut self, tree: &mut Tree, item: &[u8]) -> anyhow::Result<()>;
    async fn update_from_many_queue_items_with_tree_ref(&mut self, tree: &mut Tree, item: &[Vec<u8>]) -> anyhow::Result<()>;
    async fn finalize_with_tree_ref(self, tree: &mut Tree) -> anyhow::Result<Self::Output>;
}
#[async_trait]
impl<C: Send + Sync + 'static, Tree: Send + Sync + 'static, T: QueueGathererItemBuilderWithTreeRef<C, Tree> + Send + Sync> QueueGathererItemBuilderWithTree<C, Tree> for T {
    type Output = T::Output;

    async fn create_new_with_tree(tree: &mut Tree, unique_id: u128, config: C) -> anyhow::Result<Self> {
        T::create_new_with_tree_ref(tree, unique_id, config).await
    }

    async fn update_from_queue_item_with_tree(&mut self, tree: &mut Tree, item: Vec<u8>) -> anyhow::Result<()> {
        self.update_from_queue_item_with_tree_ref(tree, &item).await
    }

    async fn update_from_many_queue_items_with_tree(&mut self, tree: &mut Tree, item: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.update_from_many_queue_items_with_tree_ref(tree, &item).await
    }

    async fn finalize_with_tree(self, tree: &mut Tree) -> anyhow::Result<Self::Output> {
        self.finalize_with_tree_ref(tree).await
    }
}

#[async_trait]
pub trait QueueGathererItemBuilderRef<C>: Sized {
    type Output: Sized + Send + Sync;
    async fn create_new_ref(unique_id: u128, config: C) -> anyhow::Result<Self>;
    async fn update_from_queue_item_ref(&mut self, item: &[u8]) -> anyhow::Result<()>;
    async fn update_from_many_queue_items_ref(&mut self, item: &[Vec<u8>]) -> anyhow::Result<()> {
        for it in item {
            self.update_from_queue_item_ref(it).await?;
        }
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output>;
}
#[async_trait]
impl<T: QueueGathererItemBuilderRef<C> + Send + Sync, C: Clone + Send + Sync + 'static> QueueGathererItemBuilder<C> for T {
    type Output = T::Output;
    async fn create_new(unique_id: u128, config: C) -> anyhow::Result<Self> {
        T::create_new_ref(unique_id, config).await
    }
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()> {
        self.update_from_queue_item_ref(&item).await
    }
    async fn update_from_many_queue_items(&mut self, item: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.update_from_many_queue_items_ref(&item).await
    }
    async fn finalize(self) -> anyhow::Result<Self::Output> {
        T::finalize(self).await
    }
}


pub struct SimpleSerializeGathererItemBuilder<T: PsySerializeCanonicalAsyncSafe + Sized + Send + Sync> {
    pub items: Vec<T>,
}
#[async_trait]
impl <T: PsySerializeCanonicalAsyncSafe + Sized + Send + Sync> QueueGathererItemBuilder<()> for SimpleSerializeGathererItemBuilder<T> {

    type Output = Vec<T>;
    async fn create_new(_unique_id:u128, _config:()) -> anyhow::Result<Self> {
        Ok(Self { items: Vec::new() })
    }
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()>{
        self.items.push(PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_from_owned_bytes_vec(item)?);
        Ok(())
    }
    async fn update_from_many_queue_items(&mut self, item: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.items.reserve(item.len());
        for it in item {
            self.items.push(PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_from_owned_bytes_vec(it)?);
        }
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output>{
        Ok(self.items)
    }
}

pub struct DualSerializeGathererItemBuilder<B1: QueueGathererItemBuilder<C1>, C1: Clone + Send + Sync + 'static, B2: QueueGathererItemBuilder<C2>, C2: Clone + Send + Sync + 'static> {
    pub builder1: B1,
    pub builder2: B2,
    _phantom_c1: std::marker::PhantomData<C1>,
    _phantom_c2: std::marker::PhantomData<C2>,
}
#[async_trait]
impl <B1: QueueGathererItemBuilder<C1> + Send + Sync, C1: Clone + Send + Sync + 'static, B2: QueueGathererItemBuilder<C2> + Send + Sync, C2: Clone + Send + Sync + 'static> QueueGathererItemBuilder<(C1, C2)> for DualSerializeGathererItemBuilder<B1, C1, B2, C2> {   
    type Output = (B1::Output, B2::Output);
    async fn create_new(unique_id:u128, config: (C1, C2)) -> anyhow::Result<Self> {
        Ok(Self {
            builder1: B1::create_new(unique_id, config.0).await?,
            builder2: B2::create_new(unique_id, config.1).await?,
            _phantom_c1: std::marker::PhantomData,
            _phantom_c2: std::marker::PhantomData,
        })
    }
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()>{
        self.builder1.update_from_queue_item(item.clone()).await?;
        self.builder2.update_from_queue_item(item).await?;
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output>{
        Ok((
            self.builder1.finalize().await?,
            self.builder2.finalize().await?,
        ))
    }
}

#[derive(Clone)]
pub struct WriteQueueToFileGathererConfig<C> {
    pub file_path_prefix: String,
    pub file_path_suffix: String,
    pub base_config: C,
}
impl <C> WriteQueueToFileGathererConfig<C> {
    pub fn get_file_path(&self, unique_id: u128) -> String {
        format!("{}{}{}", self.file_path_prefix, unique_id, self.file_path_suffix)
    }
}


pub struct WriteQueueToFileGathererItemBuilder<C, B> {
    file: tokio::fs::File,
    builder: B,
    _phantom_c: std::marker::PhantomData<C>,
}
impl<C, B> WriteQueueToFileGathererItemBuilder<C, B> {
    fn split_parts(self) -> (tokio::fs::File, B) {
        (self.file, self.builder)
    }
}
#[async_trait]
impl<C: Clone + Send + Sync + 'static, B: QueueGathererItemBuilder<C> + Send + Sync> QueueGathererItemBuilder<WriteQueueToFileGathererConfig<C>> for WriteQueueToFileGathererItemBuilder<C, B> {
    type Output = B::Output;
    async fn create_new(unique_id:u128, config: WriteQueueToFileGathererConfig<C>) -> anyhow::Result<Self> {
        let file = tokio::fs::File::create(config.get_file_path(unique_id)).await?;
        let builder = B::create_new(unique_id, config.base_config).await?;
        Ok(Self {
            file,
            builder,
            _phantom_c: std::marker::PhantomData,
        })
    }
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()>{
        self.file.write_all(&item).await?;
        self.builder.update_from_queue_item(item).await?;
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output>{
        {
            let (mut file, builder) = self.split_parts();
            file.flush().await?;
            builder.finalize().await
        }
    }
}


pub struct WriteQueueToFileGathererItemBuilderRef<C, B> {
    file: tokio::fs::File,
    builder: B,
    _phantom_c: std::marker::PhantomData<C>,
}
impl<C, B> WriteQueueToFileGathererItemBuilderRef<C, B> {
    fn split_parts(self) -> (tokio::fs::File, B) {
        (self.file, self.builder)
    }
}


#[async_trait]
impl<C: Clone + Send + Sync + 'static, B: QueueGathererItemBuilderRef<C> + Send + Sync> QueueGathererItemBuilder<WriteQueueToFileGathererConfig<C>> for WriteQueueToFileGathererItemBuilderRef<C, B> {
    type Output = B::Output;

    async fn create_new(unique_id: u128, config: WriteQueueToFileGathererConfig<C>) -> anyhow::Result<Self> {
        let file = tokio::fs::File::create(&config.get_file_path(unique_id)).await?;
        let builder = B::create_new_ref(unique_id, config.base_config).await?;
        Ok(Self {
            file,
            builder,
            _phantom_c: std::marker::PhantomData,
        })
    }

    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()> {
        let file = &mut self.file;
        let builder = &mut self.builder;
        let item_ref: &[u8] = &item;

        let write_fut = async {
            if item_ref.len() > u32::MAX as usize {
                return Err(anyhow::anyhow!("Item too large to write to file"));
            }
            file.write_u32(item_ref.len() as u32).await?;
            file.write_all(item_ref).await?;
            Ok(())
        };

        let update_fut = builder.update_from_queue_item_ref(item_ref);

        try_join!(write_fut, update_fut)?;
        Ok(())
    }

    async fn update_from_many_queue_items(&mut self, item: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let file = &mut self.file;
        let builder = &mut self.builder;
        let items_ref: &[Vec<u8>] = &item;

        let write_fut = async {
            for it in items_ref {
                if it.len() > u32::MAX as usize {
                    return Err(anyhow::anyhow!("Item too large to write to file"));
                }
                file.write_u32(it.len() as u32).await?;
                file.write_all(it).await?;
            }
            Ok(())
        };

        let update_fut = builder.update_from_many_queue_items_ref(items_ref);

        try_join!(write_fut, update_fut)?;
        Ok(())
    }

    async fn finalize(self) -> anyhow::Result<Self::Output> {
        let (mut file, builder) = self.split_parts();
        file.flush().await?;
        builder.finalize().await
    }
}