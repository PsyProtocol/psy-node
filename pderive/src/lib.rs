use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{parse_macro_input, Attribute, ItemStruct};

#[proc_macro_attribute]
pub fn serialize_copy(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
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
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
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
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_default(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
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
            Default,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_default(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
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
            Default,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_default_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            Default,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_default_no_ord(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_attr: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            Default,
            rkyv::Archive,
            rkyv::Serialize,
            rkyv::Deserialize,
            speedy::Readable,
            speedy::Writable
        )]
    );

    // Insert at the beginning so it appears first in the output
    item_struct.attrs.insert(0, derive_attr);

    TokenStream::from(item_struct.into_token_stream())
}



