pub mod compile_bridge;
pub mod session;
pub use session::*;
pub mod utils;
pub use utils::*;

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(dur: std::time::Duration) {
    tokio::time::sleep(dur).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(dur: std::time::Duration) {
    use js_sys::{global, Function, Promise, Reflect};
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let ms = dur.as_millis() as i32;

    let promise = Promise::new(&mut |resolve: Function, _reject: Function| {
        let global_obj = global();
        let resolve_for_cb = resolve.clone();
        let cb = Closure::<dyn FnMut()>::once(move || {
            let _ = resolve_for_cb.call0(&JsValue::NULL);
        });
        if let Some(set_timeout) = Reflect::get(&global_obj, &JsValue::from_str("setTimeout"))
            .ok()
            .and_then(|v| v.dyn_into::<Function>().ok())
        {
            let _ = set_timeout.call2(
                &global_obj,
                cb.as_ref().unchecked_ref(),
                &JsValue::from_f64(ms as f64),
            );
        } else {
            let _ = resolve.call0(&JsValue::NULL);
        }
        cb.forget();
    });

    let _ = JsFuture::from(promise).await;
}
