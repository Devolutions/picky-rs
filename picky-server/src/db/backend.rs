use crate::configuration::{BackendType, ServerConfig};
use crate::db::mongodb::mongo_repos::MongoRepos;
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::memory::memory_repos::MemoryRepos;
use crate::configuration::BackendType::Memory;

pub struct Backend {
    pub db: Box<BackendStorage>
}

impl Backend {
    pub fn new(db: Box<BackendStorage>) -> Result<Self, String> {
        let mut backend = Backend{
            db
        };

        if let Err(e) = backend.db.init(){
            return Err(e);
        }

        Ok(backend)
    }

    pub fn store(&mut self, name: &str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String>{
        self.db.store(name, cert, key, key_identifier)
    }

    pub fn get_cert(&self, hash: &str, format: Option<u8>) -> Result<String, String>{
        self.db.get_cert(hash, format)
    }

    pub fn get_key(&self, hash: &str) -> Result<String, String>{
        self.db.get_key(hash)
    }

    pub fn find(&self, name: &str) -> Result<Vec<Storage>, String>{
        self.db.find(name)
    }

    pub fn init(&mut self) -> Result<(), String>{
        self.db.init()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Storage{
    pub key: String,
    pub value: String
}

pub trait BackendStorage: Send + Sync{
    fn init(&mut self) -> Result<(), String>;
    fn store(&mut self, name: &str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String>;
    fn find(&self, name: &str) -> Result<Vec<Storage>, String>;
    fn get_cert(&self, hash: &str, format: Option<u8>) -> Result<String, String>;
    fn get_key(&self, hash: &str) -> Result<String, String>;
    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>;
    fn get_hash_from_key_identifier(&self, hash: &str) -> Result<String, String>;
    fn clone_box(&self) -> Box<BackendStorage>;
    /// Return tuple (common name, certificate pem, key pem)
    fn rebuild(&mut self) -> Result<Vec<(String, String, String)>, ()>;
}

impl Clone for Box<BackendStorage>{
    fn clone(&self) -> Self{
        self.clone_box()
    }
}

impl From<&ServerConfig> for Backend{
    fn from(config: &ServerConfig) -> Self{
        match config.backend {
            BackendType::MongoDb => {
                        let conn= MongoConnection::new(&config.database.url).expect("Invalid server url");
                        let dbstorage = Box::new(MongoRepos::new(conn));
                        return Backend::new(dbstorage).expect("Wrong server configuration");
                },
            BackendType::Memory => {
                // For testing
                return Backend::new(Box::new(MemoryRepos::new())).expect("Bad configuration");
            }
            _ => panic!("not yet implemented")
        }
    }
}

pub trait Repo{
    type Instance;
    type RepoError;
    type RepoCollection;

    fn init(&mut self, db_instance: Self::Instance, name: &str) -> Result<(), String>;
    fn get_collection(&self) -> Result<Self::RepoCollection, String>;
    fn store(&mut self, key: &str, value: &str) -> Result<(), String>;
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::Server;
    use std::env;
    use crate::utils;
    use picky_core::controllers::core_controller::CoreController;

    #[test]
    fn server_with_memory_backend_test(){
        env::set_var("PICKY_BACKEND", "memory");
        let conf = ServerConfig::new();

        Server::run(conf);
    }

    static PEM: &'static str = "-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIAMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFUNOPW1
5X2Rlbi5sb2wgUm9vdCBDQTAeFw0xOTA0MjYxOTU3NDFaFw0yNDA0MjQxOTU3ND
FaMB8xHTAbBgNVBAMMFG15X2Rlbi5sb2wgQXV0aG9yaXR5MIICIjANBgkqhkiG9
w0BAQEFAAOCAg8AMIICCgKCAgEA1dnnBcD5rQ70DG/hn/iPxBZ/ppwDHeDK4bzZ
fHASOka+CzP7hc3NW0ppUt8Atj++2hOu1GR6TsJegRILkrJ9dxfOMdjoxpAWcmc
qM9vtmZOkC2RlaV5b/GtB52aQTyJF227axD0rhF+Vga55+B20XStyUwoLdJ3Tnf
iil6FWeLQNisM7sCntRe/EbzVpvc2IU+TPjsNomZYJA/Yl6Wl2Qzp4g7eRKg2DP
ZrRwiYpphuv5r0BCI8K/X1CZP18FJF6+QFDXeo0L3g8E8HIa0r3N7Yr48jd7oYr
HJHXoXmFbnQYr1x+tsj1vd91cJHXHhDAEFZuzi27PbDg+Otp38Quuiu7MPTmGac
NQAMIQzxasAf3Qm3mafIU0TRmJ7dXHlsKxjzM2OiYlLXwdIFqk/nXO/1ZSNd45s
w8Mv0ruG3Br1LPLpdw3DW49DO1T6GPFWHtY1bm5uULG3U7lJe5vzsSJ9uL3jBpT
RaYvM3+wSC0L1HPmvl1GPSmDjeafu2tSRFqptnZiQc8vuRt+pIOxjuTkxxn40WB
E+iLGjkXD1VWA6XdhT6M+Tt2Zfgl83gtOmh1o2z4jm4P1QJ4v0NHc81wOZ2ksqF
cWVDA3J3t1Um2yUfw0VxirI+ytWiAC8lzwfwnVzT8H9WIuAgcpidujxdYhnbf0W
FCsZOR/Fv81k6opVMCAwEAAaNjMGEwDwYDVR0TBAgwBgEB/wIBADAOBgNVHQ8BA
f8EBAMCAa4wHQYDVR0OBBYEFJo+UnDnuGNchrYBKXO3gNvgNCf2MB8GA1UdIwQY
MBaAFPgx7if1NT16dUqpl9iVdLyRNC9pMA0GCSqGSIb3DQEBCwUAA4ICAQA7tlP
sZhoSiIjJGfpsO+XBWZbnHLIQ8a+Cn0V1oWyOspP4jLOTT7efUQYZWIzuk3IMkb
eK71U2PDIpTSvUHAUchtNKl8YcBSU6TAPKdrk3TGb1UvglMVi+xkaVYpUYYnN+L
peeyKrN4TE/qbTiju0RYH9vo6Y68G0kZVVU5ievoqpi3tOaa0BIdTBKEvwSrmm/
lQTruPAB9rGCI95sAvsmtYJIsPfaQZA3vAxoWlOrwfh3VkMoXB1QSPFt9okXpxZ
SGE1zpnBjvreuDjSS3HmIxQBYwy4TNQ3duUnDOJAFQvnhLoUzTDprXpmDnXqqLq
ZYtpU06DYuHVIOuPGIpipUl5182YS1iCSXl2RyfbYTk2+qRYlbUkUmHVgnJMA8a
uOWhKWtXdi5eJiiSciVAYpBwFXJeSCMYuBQRHaUsXcu55i+jlfDiBVZOZkYgpje
iOoyJEjTw9KFlPIHMC2qMmPkOlQjGK+CHXMY3kwFZcpz2CgRBSgVvN7Mb+Val38
Kpskn+WYe7umSp9k0laSvJghxUGYXpVxGwNCiyojsAMUoSJ7xUx5bjfOFOL7SWC
+juKXytSs4iWqXN9igFBLPd54pj6wdAI5FieHsP6PwaM8Bt20BlJsCa1nj1uR9o
dK9RO0Wys/X1CAeFnsen7+BVKFvjx0CHZuiNgdTE+BbYBTfgg==
-----END CERTIFICATE-----";

    #[test]
    fn key_id_and_cert_test(){
        let kid = "9a3e5270e7b8635c86b6012973b780dbe03427f6";
        let cert = "3082051c30820304a0030201020200300d06092a864886f70d01010b05003020311e301c06035504030c15434e3d6d795f64656e2e6c6f6c20526f6f74204341301e170d3139303432363139353734315a170d3234303432343139353734315a301f311d301b06035504030c146d795f64656e2e6c6f6c20417574686f7269747930820222300d06092a864886f70d01010105000382020f003082020a0282020100d5d9e705c0f9ad0ef40c6fe19ff88fc4167fa69c031de0cae1bcd97c70123a46be0b33fb85cdcd5b4a6952df00b63fbeda13aed4647a4ec25e81120b92b27d7717ce31d8e8c6901672672a33dbed9993a40b6465695e5bfc6b41e766904f2245db6edac43d2b845f9581ae79f81db45d2b72530a0b749dd39df8a297a15678b40d8ac33bb029ed45efc46f3569bdcd8853e4cf8ec36899960903f625e96976433a7883b7912a0d833d9ad1c22629a61bafe6bd01088f0afd7d4264fd7c14917af901435dea342f783c13c1c86b4af737b62be3c8ddee862b1c91d7a179856e7418af5c7eb6c8f5bddf757091d71e10c010566ece2dbb3db0e0f8eb69dfc42eba2bbb30f4e619a70d400308433c5ab007f7426de669f214d1346627b7571e5b0ac63cccd8e89894b5f074816a93f9d73bfd5948d778e6cc3c32fd2bb86dc1af52cf2e9770dc35b8f433b54fa18f1561ed6356e6e6e50b1b753b9497b9bf3b1227db8bde30694d1698bccdfec120b42f51cf9af97518f4a60e379a7eedad49116aa6d9d989073cbee46dfa920ec63b93931c67e3458113e88b1a39170f555603a5dd853e8cf93b7665f825f3782d3a6875a36cf88e6e0fd50278bf434773cd70399da4b2a15c5950c0dc9dedd549b6c947f0d15c62ac8fb2b568800bc973c1fc275734fc1fd588b8081ca6276e8f17588676dfd16142b19391fc5bfcd64ea8a5530203010001a3633061300f0603551d13040830060101ff020100300e0603551d0f0101ff0404030201ae301d0603551d0e041604149a3e5270e7b8635c86b6012973b780dbe03427f6301f0603551d23041830168014f831ee27f5353d7a754aa997d89574bc91342f69300d06092a864886f70d01010b050003820201003bb653ec661a128888c919fa6c3be5c15996e71cb210f1af829f4575a16c8eb293f88cb3934fb79f510619588cee93720c91b78aef55363c32294d2bd41c051c86d34a97c61c05253a4c03ca76b9374c66f552f8253158bec6469562951862737e2e979ec8aacde1313fa9b4e28eed11607f6fa3a63af06d24655554e627afa2aa62ded39a6b404875304a12fc12ae69bf9504ebb8f001f6b18223de6c02fb26b58248b0f7da419037bc0c685a53abc1f8775643285c1d5048f16df68917a71652184d73a67063beb7ae0e3492dc7988c50058c32e13350dddb949c338900542f9e12e85334c3a6b5e99839d7aaa2ea658b69534e8362e1d520eb8f188a62a54979d7cd984b58824979764727db613936faa45895b5245261d582724c03c6ae39684a5ad5dd8b97898a249c895018a41c055c979208c62e050447694b1772ee798be8e57c38815593999188298de88ea322448d3c3d28594f207302daa3263e43a542318af821d7318de4c0565ca73d82811052815bcdecc6fe55a977f0aa6c927f9661eeee992a7d93495a4af260871506617a55c46c0d0a2ca88ec00c528489ef1531e5b8df38538bed2582fa3b8a5f2b52b38896a9737d8a01412cf779e298fac1d008e4589e1ec3fa3f068cf01b76d01949b026b59e3d6e47da1d2bd44ed16cacfd7d4201e167b1e9fbf8154a16f8f1d021d9ba236075313e05b6014df82";
        let cert = utils::der_to_pem(cert.as_bytes());

        let key_id = CoreController::get_key_identifier(&cert, &[2, 5, 29, 14]).unwrap();
        let key_id_pem = CoreController::get_key_identifier(PEM, &[2, 5, 29, 14]).unwrap();

        assert_eq!(key_id, key_id_pem);
        assert_eq!(&key_id, kid);
    }
}