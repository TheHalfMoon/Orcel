//! The GTK4 window. No `gtk::Application` is used: an application id would
//! let another process that owns the same id on the session bus receive the
//! activation instead of this one.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use gtk::glib;
use gtk::prelude::*;
use gtk4 as gtk;

use crate::protocol::Request;

/// Approve stays insensitive this long, so a keypress or click already on
/// its way when the window appears cannot approve.
const APPROVE_DELAY: Duration = Duration::from_millis(1500);

/// Shows the request and returns the person's answer, or `None` when GTK
/// cannot open a display.
pub fn ask(request: &Request) -> Option<bool> {
    gtk::init().ok()?;

    let answer: Rc<Cell<Option<bool>>> = Rc::new(Cell::new(None));
    let main_loop = glib::MainLoop::new(None, false);
    let decide: Rc<dyn Fn(bool)> = {
        let answer = answer.clone();
        let main_loop = main_loop.clone();
        Rc::new(move |approved: bool| {
            // The first answer counts; a later event changes nothing.
            if answer.get().is_none() {
                answer.set(Some(approved));
            }
            main_loop.quit();
        })
    };

    let window = gtk::Window::builder()
        .title(request.title.as_str())
        .modal(true)
        .default_width(620)
        .default_height(460)
        .build();

    // Plain text, never markup: the body is shown exactly as sent.
    let body = gtk::Label::new(Some(request.body.as_str()));
    body.set_use_markup(false);
    body.set_wrap(true);
    body.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    body.set_max_width_chars(80);
    body.set_xalign(0.0);
    body.set_yalign(0.0);
    body.set_selectable(false);

    let scroller = gtk::ScrolledWindow::builder()
        .child(&body)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .hexpand(true)
        .build();

    let deny = gtk::Button::with_label("Deny");
    let approve = gtk::Button::with_label("Approve");
    approve.add_css_class("destructive-action");
    approve.set_sensitive(false);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    buttons.set_halign(gtk::Align::End);
    buttons.append(&deny);
    buttons.append(&approve);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(18);
    content.set_margin_start(18);
    content.set_margin_end(18);
    content.append(&scroller);
    content.append(&buttons);
    window.set_child(Some(&content));
    // Return activates Deny.
    window.set_default_widget(Some(&deny));

    deny.connect_clicked({
        let decide = decide.clone();
        move |_| decide(false)
    });
    approve.connect_clicked({
        let decide = decide.clone();
        move |_| decide(true)
    });
    window.connect_close_request({
        let decide = decide.clone();
        move |_| {
            decide(false);
            glib::Propagation::Proceed
        }
    });
    let keys = gtk::EventControllerKey::new();
    keys.connect_key_pressed({
        let decide = decide.clone();
        move |_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                decide(false);
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        }
    });
    window.add_controller(keys);

    glib::timeout_add_local_once(APPROVE_DELAY, {
        let approve = approve.clone();
        move || approve.set_sensitive(true)
    });
    glib::timeout_add_local_once(Duration::from_secs(request.timeout_secs), {
        let decide = decide.clone();
        move || decide(false)
    });

    window.present();
    deny.grab_focus();
    main_loop.run();

    window.destroy();
    let context = glib::MainContext::default();
    while context.iteration(false) {}
    answer.get()
}
