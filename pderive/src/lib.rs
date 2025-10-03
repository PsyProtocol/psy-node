use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{parse_macro_input, Attribute, ItemStruct};

#[proc_macro_attribute]
pub fn serialize_copy(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_default(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
            Default
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_default(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
            Default
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_default_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            Default
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_default_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            Default
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}