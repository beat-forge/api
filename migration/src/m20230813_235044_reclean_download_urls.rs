use sea_orm_migration::{prelude::*, sea_orm::{EntityTrait, IntoActiveModel, ActiveModelTrait}};
use entity::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reset all db download URLs
        let db = manager.get_connection();
        let vers = Versions::find().all(db).await.unwrap();
        for mut v in vers {
            let parent = Mods::find_by_id(v.mod_id)
                .one(db)
                .await
                .unwrap()
                .unwrap();
            v.download_url = format!(
                "{}/cdn/{}@{}",
                std::env::var("PUBLIC_URL").unwrap(),
                parent.slug,
                v.version
            );
            v.into_active_model().save(db).await.unwrap();
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
