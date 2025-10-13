use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{parse_macro_input, Attribute, ItemStruct};

#[proc_macro_attribute]
pub fn serialize_copy_f_hash(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize, for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}

#[proc_macro_attribute]
pub fn serialize_clone_f_hash(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize, for<'de2> F: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_f_hash_ts(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize, for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_bound: Attribute = syn::parse_quote!(
        #[ts(bound = "F: ts_rs::TS, Hash: ts_rs::TS")]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_bound);
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}

#[proc_macro_attribute]
pub fn serialize_clone_f_hash_ts(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize, for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_bound: Attribute = syn::parse_quote!(
        #[ts(bound = "F: ts_rs::TS, Hash: ts_rs::TS")]
    );


    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_bound);
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_hash_ts(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_bound: Attribute = syn::parse_quote!(
        #[ts(bound = "Hash: ts_rs::TS")]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_bound);
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_hash(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_hash_ts(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_bound: Attribute = syn::parse_quote!(
        #[ts(bound = "Hash: ts_rs::TS")]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_bound);
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_copy_f_ts(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let serde_bound: Attribute = syn::parse_quote!(
        #[serde(bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize")]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_bound: Attribute = syn::parse_quote!(
        #[ts(bound = "F: ts_rs::TS")]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_bound);
    item_struct.attrs.insert(0, serde_bound);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}
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
pub fn serialize_copy_ts_export(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_export : Attribute = syn::parse_quote!(
        #[ts(export)]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_export);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}


#[proc_macro_attribute]
pub fn serialize_clone_ts_export(_attr: TokenStream, input: TokenStream) -> TokenStream {
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
            ts_rs::TS,
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
    let ts_export : Attribute = syn::parse_quote!(
        #[ts(export)]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, ts_export);
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);
    item_struct.attrs.insert(0, derive_serde);

    TokenStream::from(item_struct.into_token_stream())
}

#[proc_macro_attribute]
pub fn non_serde_serialize(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);

    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );

    // Insert attributes in reverse order to maintain the desired output order
    item_struct.attrs.insert(0, derive_speedy);
    item_struct.attrs.insert(0, derive_rkyv);

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