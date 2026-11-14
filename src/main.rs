//! Executable entry point that delegates server startup to the library.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    project_charlotte::run()
}
