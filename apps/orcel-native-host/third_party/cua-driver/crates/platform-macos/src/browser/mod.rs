#[cfg(not(feature = "orcel-minimal"))]
pub mod ax_page_reader;
pub mod browser_js;
#[cfg(not(feature = "orcel-minimal"))]
pub mod cdp_client;
#[cfg(not(feature = "orcel-minimal"))]
mod consent_ui;
pub mod electron_js;
#[cfg(not(feature = "orcel-minimal"))]
pub mod platform;
#[cfg(not(feature = "orcel-minimal"))]
mod setup_ui;
#[cfg(not(feature = "orcel-minimal"))]
pub mod wk_web_view;

#[cfg(not(feature = "orcel-minimal"))]
pub use ax_page_reader::AXPageReader;
pub use browser_js::BrowserJs;
#[cfg(not(feature = "orcel-minimal"))]
pub use cdp_client::{CdpClient, CdpSessionCache};
pub use electron_js::ElectronJs;
#[cfg(not(feature = "orcel-minimal"))]
pub use platform::MacOsBrowserPlatform;
#[cfg(not(feature = "orcel-minimal"))]
pub use wk_web_view::is_wk_web_view_app;
