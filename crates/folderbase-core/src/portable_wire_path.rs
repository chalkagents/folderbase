//! Canonical JSON representation for migration paths.
//!
//! Filesystem paths remain native `PathBuf` values in memory. At a durable or
//! public JSON boundary, separators are always `/`. A literal backslash in a
//! Unix path component is rejected instead of being confused with a Windows
//! separator.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};

const BACKSLASH_COMPONENT_ERROR: &str =
    "migration wire path component contains a forbidden backslash character";
const BACKSLASH_WIRE_ERROR: &str =
    "migration wire paths use '/' separators; backslash characters are forbidden";
const NUL_ERROR: &str = "migration wire paths cannot contain NUL characters";

fn native_to_wire(path: &Path) -> Result<Cow<'_, str>, &'static str> {
    let native = path
        .to_str()
        .ok_or("migration wire paths must contain valid UTF-8")?;
    if native.contains('\0') {
        return Err(NUL_ERROR);
    }

    #[cfg(windows)]
    {
        Ok(Cow::Owned(native.replace('\\', "/")))
    }

    #[cfg(not(windows))]
    {
        if native.contains('\\') {
            return Err(BACKSLASH_COMPONENT_ERROR);
        }
        Ok(Cow::Borrowed(native))
    }
}

fn validate_relative(path: &Path) -> Result<(), &'static str> {
    let mut saw_component = false;
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("migration relative wire paths contain only ordinary path components");
        };
        let component = component
            .to_str()
            .ok_or("migration wire paths must contain valid UTF-8")?;
        if component.contains('\\') {
            return Err(BACKSLASH_COMPONENT_ERROR);
        }
        if component.contains('\0') {
            return Err(NUL_ERROR);
        }
        saw_component = true;
    }
    if !saw_component {
        return Err("migration relative wire paths cannot be empty");
    }
    Ok(())
}

pub(crate) fn relative_to_wire(path: &Path) -> Result<String, &'static str> {
    validate_relative(path)?;
    path.components()
        .map(|component| match component {
            Component::Normal(component) => component
                .to_str()
                .map(ToOwned::to_owned)
                .ok_or("migration wire paths must contain valid UTF-8"),
            _ => Err("migration relative wire paths contain only ordinary path components"),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn relative_from_wire(value: &str) -> Result<PathBuf, &'static str> {
    if value.contains('\\') {
        return Err(BACKSLASH_WIRE_ERROR);
    }
    if value.contains('\0') {
        return Err(NUL_ERROR);
    }
    if value.is_empty() {
        return Err("migration relative wire paths cannot be empty");
    }
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || (value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && value.as_bytes().get(1) == Some(&b':'))
    {
        return Err("migration relative wire path is not canonical");
    }
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err("migration relative wire path is not canonical");
        }
        path.push(component);
    }
    validate_relative(&path)?;
    Ok(path)
}

fn display_from_wire(value: &str) -> Result<PathBuf, &'static str> {
    if value.contains('\\') {
        return Err(BACKSLASH_WIRE_ERROR);
    }
    if value.contains('\0') {
        return Err(NUL_ERROR);
    }
    #[cfg(windows)]
    {
        Ok(PathBuf::from(value.replace('/', "\\")))
    }

    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(value))
    }
}

pub(crate) mod relative {
    use super::*;

    pub(crate) fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&relative_to_wire(path).map_err(S::Error::custom)?)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        relative_from_wire(&value).map_err(D::Error::custom)
    }

    pub(crate) mod option {
        use super::*;

        pub(crate) fn serialize<S>(path: &Option<PathBuf>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match path {
                Some(path) => {
                    serializer.serialize_some(&relative_to_wire(path).map_err(S::Error::custom)?)
                }
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<String>::deserialize(deserializer)?
                .map(|value| relative_from_wire(&value).map_err(D::Error::custom))
                .transpose()
        }
    }

    pub(crate) mod vec {
        use super::*;

        pub(crate) fn serialize<S>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let paths = paths
                .iter()
                .map(|path| relative_to_wire(path).map_err(S::Error::custom))
                .collect::<Result<Vec<_>, _>>()?;
            paths.serialize(serializer)
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PathBuf>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Vec::<String>::deserialize(deserializer)?
                .into_iter()
                .map(|value| relative_from_wire(&value).map_err(D::Error::custom))
                .collect()
        }
    }

    pub(crate) mod map {
        use super::*;

        pub(crate) fn serialize<S, V>(
            paths: &BTreeMap<PathBuf, V>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            V: Serialize,
        {
            let mut encoded = BTreeMap::new();
            for (path, value) in paths {
                let path = relative_to_wire(path).map_err(S::Error::custom)?;
                if encoded.insert(path, value).is_some() {
                    return Err(S::Error::custom(
                        "migration wire path map contains colliding canonical keys",
                    ));
                }
            }
            encoded.serialize(serializer)
        }

        pub(crate) fn deserialize<'de, D, V>(
            deserializer: D,
        ) -> Result<BTreeMap<PathBuf, V>, D::Error>
        where
            D: Deserializer<'de>,
            V: Deserialize<'de>,
        {
            let mut decoded = BTreeMap::new();
            for (path, value) in BTreeMap::<String, V>::deserialize(deserializer)? {
                let path = relative_from_wire(&path).map_err(D::Error::custom)?;
                if decoded.insert(path, value).is_some() {
                    return Err(D::Error::custom(
                        "migration wire path map contains colliding canonical keys",
                    ));
                }
            }
            Ok(decoded)
        }
    }
}

pub(crate) mod relative_or_current {
    use super::*;

    pub(crate) fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if path == Path::new(".") {
            serializer.serialize_str(".")
        } else {
            serializer.serialize_str(&relative_to_wire(path).map_err(S::Error::custom)?)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "." {
            Ok(PathBuf::from("."))
        } else {
            relative_from_wire(&value).map_err(D::Error::custom)
        }
    }
}

pub(crate) mod relative_or_empty {
    use super::*;

    pub(crate) fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if path.as_os_str().is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str(&relative_to_wire(path).map_err(S::Error::custom)?)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() {
            Ok(PathBuf::new())
        } else {
            relative_from_wire(&value).map_err(D::Error::custom)
        }
    }
}

pub(crate) mod display {
    use super::*;

    pub(crate) fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(native_to_wire(path).map_err(S::Error::custom)?.as_ref())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        display_from_wire(&value).map_err(D::Error::custom)
    }
}
