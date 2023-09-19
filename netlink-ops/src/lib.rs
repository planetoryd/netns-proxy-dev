#![feature(negative_impls)]
#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
#![feature(assert_matches)]
#![feature(generators, generator_trait)]
#![feature(error_generic_member_access)]
#![feature(associated_type_defaults)]
#![feature(iterator_try_collect)]
#![feature(hash_extract_if)]
#![feature(let_chains)]
#![feature(impl_trait_in_assoc_type)]
#![feature(decl_macro)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]
#![allow(unused)]

pub mod netlink;
pub mod nft;
pub mod state;
pub mod netns;
pub mod errors;