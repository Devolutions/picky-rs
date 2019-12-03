pub mod server_controller;

pub mod utils {
    use saphir::SyncRequest;

    pub trait SyncRequestUtil {
        fn get_header_string_value(&self, header_name: &str) -> Option<String>;
    }

    impl SyncRequestUtil for SyncRequest {
        fn get_header_string_value(&self, header_name: &str) -> Option<String> {
            if let Some(hdr) = self.headers_map().get(header_name) {
                if let Ok(hdr_value) = hdr.to_str() {
                    if !hdr_value.is_empty() {
                        return Some(hdr_value.to_string());
                    }
                }
            }
            None
        }
    }
}
