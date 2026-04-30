fn main() {
    #[cfg(target_os = "windows")]
    {
        embed_resource::compile("resource.rc", [] as [&str; 0]);
    }
}
