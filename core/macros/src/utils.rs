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
