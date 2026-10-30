// The single strip above the page content that carries system notices — today
// the subscription state and an available update.
//
// ⛔ THEY USED TO BE TWO INDEPENDENT FULL-BLEED TINTED BANNERS, and together
// they were 9.3% of the Overview's content pixels and TWO of the seven surface
// levels that page was drawing (measured against ExDomainVault, which draws two
// in total for its whole content area). Each notice is still independently
// conditional and independently dismissible — nothing about WHEN a notice shows
// has changed. What changed is that they share one quiet strip, and tone is
// carried by a dot rather than by a coloured ground.
//
// ⛔ `bad` KEEPS ITS GROUND. A lapsed subscription is genuinely risk and this
// product's own rule is that colour means risk; a renewal still weeks away is
// an action to schedule, and a full-width amber band for it was the chrome
// breaking the rule the palette keeps. ⛔ The WORDS then carry what the ground
// no longer does — see licenceSentence() in lib/productLicense.js.
// See also the ⛔ block beside .notice-bar in app/globals.css.

export function NoticeBar({ children }) {
  return <div className="notice-bar">{children}</div>;
}

/**
 * One notice. Rendered by the notifier components, never directly by a page.
 *
 * @param {'info'|'warn'|'bad'} tone
 * @param {React.ReactNode} children  the sentence
 * @param {React.ReactNode} [action]  a link, already built by the caller
 * @param {() => void} [onDismiss]    omitted => the notice cannot be dismissed
 */
export function NoticeRow({ tone = 'info', children, action, onDismiss }) {
  return (
    <div className="notice-row" data-tone={tone} role="status">
      <span className="notice-dot" aria-hidden="true" />
      <span className="notice-text">{children}</span>
      {action}
      {onDismiss ? (
        <button type="button" className="notice-dismiss" onClick={onDismiss} aria-label="Dismiss">
          ×
        </button>
      ) : null}
    </div>
  );
}
