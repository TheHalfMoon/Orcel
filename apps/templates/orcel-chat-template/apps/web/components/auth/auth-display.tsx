import type { ReactNode } from "react";
import { AUTH_HINT_COOKIE_NAME, AUTH_HINT_COOKIE_VALUE } from "@/lib/auth-hint";

const AUTH_DISPLAY_ATTRIBUTE = "data-orcel-auth-display";

const authDisplayScript = `
(() => {
  try {
    const loggedIn = document.cookie
      .split("; ")
      .some((cookie) => cookie === ${JSON.stringify(
        `${AUTH_HINT_COOKIE_NAME}=${AUTH_HINT_COOKIE_VALUE}`,
      )});
    document.documentElement.dataset.orcelAuthDisplay = loggedIn
      ? "logged-in"
      : "logged-out";
  } catch {
    document.documentElement.dataset.orcelAuthDisplay = "logged-out";
  }
})();
`;

export function AuthDisplayPreHydrationHead() {
  return (
    <>
      <style>{`
html[${AUTH_DISPLAY_ATTRIBUTE}="logged-in"] [${AUTH_DISPLAY_ATTRIBUTE}="logged-out"],
html[${AUTH_DISPLAY_ATTRIBUTE}="logged-out"] [${AUTH_DISPLAY_ATTRIBUTE}="logged-in"] {
  display: none !important;
}
`}</style>
      <noscript>
        <style>{`[${AUTH_DISPLAY_ATTRIBUTE}="logged-in"] { display: none !important; }`}</style>
      </noscript>
      <script dangerouslySetInnerHTML={{ __html: authDisplayScript }} id="orcel-auth-display-init" />
    </>
  );
}

export function AuthDisplayLoggedIn({ children }: { readonly children: ReactNode }) {
  return (
    <div className="contents" data-orcel-auth-display="logged-in">
      {children}
    </div>
  );
}

export function AuthDisplayLoggedOut({ children }: { readonly children: ReactNode }) {
  return (
    <div className="contents" data-orcel-auth-display="logged-out">
      {children}
    </div>
  );
}
