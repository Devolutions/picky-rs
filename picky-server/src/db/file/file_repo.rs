use std::fs::File;
use crate::db::backend::Repo;
use std::fmt::Error;
use std::marker::PhantomData;
use std::io::Write;

const DEFAULT_PATH: &str = "../filebase/";
const PATH_DELIMITER: char = '/';

#[derive(Clone)]
pub struct FileRepo<T> {
    pub repo: String,
    pub phantom_data: PhantomData<T>
}

impl<T> Repo<T> for FileRepo<T> where T: Eq + Clone + AsRef<[u8]>{
    type Instance = Option<String>;
    type RepoError = Error;
    type RepoCollection = Vec<String>;

    fn init(&mut self, db_instance: Option<String>, name: &str) -> Result<(), String>{
        match db_instance {
            Some(mut path) => {
                if !path.ends_with(PATH_DELIMITER){
                    path.push(PATH_DELIMITER);
                }
                path.push_str(name);
                if let Err(e) = std::fs::create_dir_all(&path){
                    return Err(e.to_string());
                }

                self.repo = path.clone();
                Ok(())
            },
            None => {
                let path = format!("{}{}", DEFAULT_PATH, name);
                if let Err(e) = std::fs::create_dir_all(&path){
                    return Err(e.to_string());
                }

                self.repo = path.clone();
                Ok(())
            }
        }
    }

    fn get_collection(&self) -> Result<Self::RepoCollection, String> {
        let mut coll = Vec::new();
        if let Ok(d) = std::fs::read_dir(&self.repo){
            for f in d{
                let f = f.expect("Error looking for directory");
                coll.push(f.file_name().into_string().expect("Error writing filename from OsString"));
            }
        }

        Ok(coll)
    }

    fn insert(&mut self, key: &str, value: &T) -> Result<(), String> {
        if !self.repo.ends_with(PATH_DELIMITER){
            self.repo.push(PATH_DELIMITER);
        }

        if let Ok(mut file) = File::create(format!("{}{}", &self.repo, key)){
            file.write_all(value.as_ref()).expect(&format!("Error writing data to {}", key));
            return Ok(());
        }

        Err(format!("Could not create file for {} : ", key))
    }
}