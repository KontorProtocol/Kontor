use syn::PathArguments;

pub fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Option"
                    && matches!(segment.arguments, PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_result_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| {
                segment.ident == "Result"
                    && matches!(segment.arguments, syn::PathArguments::AngleBracketed(_))
            })
            .unwrap_or(false)
    } else {
        false
    }
}

pub fn is_primitive_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last().map(|s| s.ident.to_string());
        matches!(segment.as_deref(), Some("u64" | "i64" | "String"))
    } else {
        false
    }
}

pub fn is_map_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "Map")
            .unwrap_or(false)
    } else {
        false
    }
}
