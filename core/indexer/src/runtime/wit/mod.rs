mod resources;

use core::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};

pub use resources::{
    CoreContext, FallContext, HasContractId, Keys, ProcContext, ProcStorage, Signer, ViewContext,
    ViewStorage,
};

wasmtime::component::bindgen!({
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/context/signer": Signer,
        "kontor:built-in/context/view-context": ViewContext,
        "kontor:built-in/context/proc-context": ProcContext,
        "kontor:built-in/context/fall-context": FallContext,
        "kontor:built-in/context/core-context": CoreContext,
        "kontor:built-in/context/view-storage": ViewStorage,
        "kontor:built-in/context/proc-storage": ProcStorage,
        "kontor:built-in/context/keys": Keys,
    },
    additional_derives: [stdlib::Wavey],
    imports: {
        "kontor:built-in/context": async | store | trappable,
        "kontor:built-in/crypto": async | store | trappable,
        "kontor:built-in/foreign": async | store | trappable,
        "kontor:built-in/numbers": async | store | trappable,
        default: async | trappable,
    }
});

impl Serialize for kontor::built_in::foreign::ContractAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("height", &self.height)?;
        map.serialize_entry("tx_index", &self.tx_index)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for kontor::built_in::foreign::ContractAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContractAddressVisitor;

        impl<'de> Visitor<'de> for ContractAddressVisitor {
            type Value = kontor::built_in::foreign::ContractAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with `name`, `height`, and `tx_index` fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut name: Option<String> = None;
                let mut height: Option<u64> = None;
                let mut tx_index: Option<u64> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "name" => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "height" => {
                            if height.is_some() {
                                return Err(de::Error::duplicate_field("height"));
                            }
                            height = Some(map.next_value()?);
                        }
                        "tx_index" => {
                            if tx_index.is_some() {
                                return Err(de::Error::duplicate_field("tx_index"));
                            }
                            tx_index = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["name", "height", "tx_index"],
                            ));
                        }
                    }
                }

                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
                let height = height.ok_or_else(|| de::Error::missing_field("height"))?;
                let tx_index = tx_index.ok_or_else(|| de::Error::missing_field("tx_index"))?;

                Ok(kontor::built_in::foreign::ContractAddress {
                    name,
                    height,
                    tx_index,
                })
            }
        }

        deserializer.deserialize_map(ContractAddressVisitor)
    }
}

impl std::str::FromStr for kontor::built_in::foreign::ContractAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 3 {
            return Err(format!("expected 3 parts separated by '_', got: {s}"));
        }
        let name = parts[0].to_string();
        let height = parts[1]
            .parse::<u64>()
            .map_err(|e| format!("invalid height: {e}"))?;
        let tx_index = parts[2]
            .parse::<u64>()
            .map_err(|e| format!("invalid tx_index: {e}"))?;

        Ok(kontor::built_in::foreign::ContractAddress {
            name,
            height,
            tx_index,
        })
    }
}
