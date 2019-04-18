pub struct DbController<T> where T: DbStorage{
    db: T
}

impl <T>DbController<T> where T: DbStorage{
    pub fn new(db: T) -> Result<Self, String> {
        let mut db_controller = DbController{
            db
        };

        if let Err(e) = db_controller.db.init(){
            return Err(e);
        }

        Ok(db_controller)
    }

    pub fn store(&self, name: &str, cert: &str, key: &str) -> Result<bool, String>{
        self.db.store(name, cert, key)
    }

    pub fn get(&self, hash: &str) -> Result<Option<(String, String)>, String>{
        self.db.get(hash)
    }

    pub fn find(&self, name: &str) -> Result<Vec<Storage>, String>{
        self.db.find(name)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Storage{
    pub key: String,
    pub value: String
}

pub trait DbStorage{
    fn init(&mut self) -> Result<(), String>;
    fn store(&self, name: &str, cert: &str, key: &str) -> Result<bool, String>;
    fn get(&self, hash: &str) -> Result<Option<(String, String)>, String>;
    fn find(&self, name: &str) -> Result<Vec<Storage>, String>;
    fn link_cert(&self, child: &str, name: &str) -> Result<bool, String>;
}

pub trait Repo{
    type Instance;
    type RepoError;
    type RepoCollection;

    fn init(&mut self, db_instance: Self::Instance, name: &str) -> Result<(), String>;
    fn get_collection(&self) -> Result<Self::RepoCollection, String>;
    fn store(&self, key: &str, value: &str) -> Result<(), String>;
}