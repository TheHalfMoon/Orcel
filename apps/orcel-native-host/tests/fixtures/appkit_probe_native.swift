// Synthetic Orcel XP-06/11 real-Mac fixture. Adapted from native AppKit harness.
import AppKit
final class ProbeDelegate: NSObject, NSApplicationDelegate {
    let nonce: String
    let secret: String
    var windows: [NSWindow] = []
    init(_ n:String,_ s:String) { nonce=n; secret=s }
    func newWindow(title:String, top:CGFloat) -> NSWindow {
        let w=NSWindow(contentRect:NSRect(x:200,y:top,width:420,height:200),styleMask:[.titled,.closable],backing:.buffered,defer:false)
        w.title=title
        w.isReleasedWhenClosed=false
        windows.append(w)
        w.makeKeyAndOrderFront(nil)
        return w
    }
    @objc func submit(_ sender:NSButton) { /* synthetic button only */ }
    func applicationDidFinishLaunching(_ notification:Notification) {
        let w=newWindow(title:"Orcel XP06 Probe "+nonce, top:420)
        let plain=NSTextField(frame:NSRect(x:20,y:130,width:380,height:24))
        plain.stringValue="visible-"+nonce
        plain.setAccessibilityLabel("Plain field")
        plain.setAccessibilityIdentifier("xp06-plain")
        w.contentView?.addSubview(plain)
        let hidden=NSSecureTextField(frame:NSRect(x:20,y:90,width:380,height:24))
        hidden.stringValue=secret
        hidden.setAccessibilityLabel("Sign in")
        hidden.setAccessibilityIdentifier("xp06-password")
        w.contentView?.addSubview(hidden)
        let button=NSButton(title:"Submit",target:self,action:#selector(submit(_:)))
        button.frame=NSRect(x:20,y:30,width:120,height:32)
        button.setAccessibilityIdentifier("xp06-submit")
        w.contentView?.addSubview(button)
        _=newWindow(title:"Orcel Approval Probe "+nonce,top:120)
        w.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps:true)
    }
}
@main struct ProbeMain {
 static func main() {
   guard CommandLine.arguments.count==3 else { fputs("nonce and secret required\n",stderr); exit(2) }
   let app=NSApplication.shared
   let d=ProbeDelegate(CommandLine.arguments[1],CommandLine.arguments[2])
   app.setActivationPolicy(.regular)
   app.delegate=d
   app.run()
   withExtendedLifetime(d){}
 }
}
