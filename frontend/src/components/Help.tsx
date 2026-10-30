import { useContext, useState, type ReactNode } from "react";
import { CircleHelp, Search, X } from "lucide-react";
import { LocaleContext, useT } from "../i18n";
import {
  article,
  helpByFeature,
  helpCatalogs,
  type HelpId,
} from "../help/catalog";

export function HelpButton({ id, feature }: { id?: HelpId; feature?: string }) {
  const { language } = useContext(LocaleContext),
    t = useT(),
    [open, setOpen] = useState(false);
  const selected = id || helpByFeature[feature || ""] || "getting-started";
  const content = article(language, selected);
  return (
    <>
      <button
        type="button"
        className="help-button"
        aria-label={t("help") + ": " + content.title}
        title={content.title}
        data-help-id={selected}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen(true);
        }}
      >
        <CircleHelp size={15} />
      </button>
      {open && (
        <div className="help-backdrop" onClick={() => setOpen(false)}>
          <section
            className="help-dialog"
            role="dialog"
            aria-modal="true"
            aria-label={content.title}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-heading">
              <h2>{content.title}</h2>
              <button
                type="button"
                className="icon-button"
                aria-label={t("close")}
                onClick={() => setOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="modal-content">
              <p>{content.body}</p>
              <a href="#help" onClick={() => setOpen(false)}>
                {t("helpCenter")}
              </a>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
export function HelpAction({
  feature,
  children,
}: {
  feature: string;
  children: ReactNode;
}) {
  return (
    <span className="help-action">
      {children}
      <HelpButton feature={feature} />
    </span>
  );
}
export function HelpCenter() {
  const { language } = useContext(LocaleContext),
    t = useT(),
    [query, setQuery] = useState("");
  const articles = Object.entries(helpCatalogs[language].articles).filter(
    ([, a]) =>
      (a.title + " " + a.body)
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>{t("helpCenter")}</h1>
          <p>{t("helpIntro")}</p>
        </div>
        <HelpButton id="getting-started" />
      </div>
      <div className="search help-search">
        <Search size={18} />
        <input
          aria-label={t("searchHelp")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("searchHelp")}
        />
      </div>
      <div className="help-grid">
        {articles.map(([id, a]) => (
          <article className="card help-article" key={id} id={"help-" + id}>
            <h2>{a.title}</h2>
            <p>{a.body}</p>
          </article>
        ))}
      </div>
      {!articles.length && <p>{t("empty")}</p>}
    </>
  );
}
