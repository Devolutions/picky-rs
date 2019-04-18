/*use crate::controllers::db_controller::Repo;
use crate::db::mongodb::mongo_repos::RepositoryError;
use crate::db::mongodb::mongo_connection::MongoConnection;
use mongodb::coll::Collection;

pub struct MongoKey{
    db_instance: Option<MongoConnection>
}

impl MongoKey{

}

impl Default for MongoKey{
    fn default() -> Self{
        MongoKey{
            db_instance: None
        }
    }
}

impl Repo for MongoKey{
    type Instance = MongoConnection;
    type RepoError = RepositoryError;
    type RepoCollection = Collection;

    fn init(&mut self, db_instance: Instance) -> Result<(), RepoError>{

    }

    fn get_collection(&self) -> Result<RepoCollection, RepoErro>{

    }

    fn store(&self, key: &str, value: &str) -> Result<bool, RepoError>{

    }
}*/