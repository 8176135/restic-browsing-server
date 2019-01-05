extern crate rocket_contrib;
extern crate urlencoding;

use rocket_contrib::templates::{handlebars::{Helper, Handlebars, Context, RenderContext, Output, HelperResult, JsonRender}};

pub fn url_encode_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output)
    -> HelperResult {
    if let Some(param) = h.param(0) {
        out.write(&urlencoding::encode(&param.value().render())).expect("Failed to write url helper");
    }
    Ok(())
}

pub fn to_upper_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output)
    -> HelperResult {
    if let Some(param) = h.param(0) {
        out.write(&param.value().render().to_uppercase()).expect("Failed to write uppercase helper");
        ;
    }
    Ok(())
}
