// Shared test fixture: a launch frame matching the Rust build_worker_argv output.

import type { HostFrame } from "./protocol.js";

export function validLaunch(): Extract<HostFrame, { frame: "launch" }> {
  const profile = "C:\\Users\\me\\AppData\\Local\\Orcel\\browser\\profile";
  return {
    frame: "launch",
    engine: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    profile_dir: profile,
    argv: [
      "--headless",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-sync",
      "--no-service-autorun",
      `--user-data-dir=${profile}`,
      "--remote-debugging-pipe",
      "--host-resolver-rules=MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND",
      "--proxy-server=http://0.0.0.0:9",
      "--proxy-bypass-list=example.com;<-loopback>",
      "--webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--disable-quic",
      "--disable-blink-features=SharedWorker",
      "--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msForceOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns,HttpsFirstBalancedModeAutoEnable",
      "about:blank"
    ],
    env: { SystemRoot: "C:\\Windows", PATH: "C:\\Windows\\System32", TEMP: "C:\\Windows\\Temp" }
  };
}
