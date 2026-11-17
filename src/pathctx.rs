use std::{io, path::Path};

pub(crate) trait PathContext<T> {
    fn path_context(self, action: &str, path: &Path) -> io::Result<T>;
}

impl<T> PathContext<T> for io::Result<T> {
    fn path_context(self, action: &str, path: &Path) -> io::Result<T> {
        self.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not {action} {}: {error}", path.display()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{io, path::Path};

    use super::PathContext;

    #[test]
    fn preserves_error_kind_and_adds_path() {
        let path = Path::new("/tmp/protected.conf");
        let error = Err::<(), _>(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
            .path_context("read config", path)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("/tmp/protected.conf"));
        assert!(error.to_string().contains("denied"));
    }
}
