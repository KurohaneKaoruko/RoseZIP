import React, { createContext, useCallback, useContext, useState } from "react";
import { Icon } from "./icons";

/* ------------------------------------------------------------------ */
/* Buttons & form primitives                                           */
/* ------------------------------------------------------------------ */

export function Spinner({ size = 14 }) {
  return <span className="spinner" style={{ width: size, height: size }} aria-hidden="true" />;
}

export function Button({
  variant = "primary",
  size,
  icon,
  iconRight,
  loading = false,
  children,
  className = "",
  disabled,
  ...rest
}) {
  return (
    <button
      className={`btn btn-${variant} ${size === "sm" ? "btn-sm" : ""} ${className}`.trim()}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Spinner /> : icon ? <Icon name={icon} size={15} /> : null}
      {children}
      {iconRight && !loading ? <Icon name={iconRight} size={14} /> : null}
    </button>
  );
}

export function IconButton({ icon, label, className = "", ...rest }) {
  return (
    <button className={`icon-btn ${className}`.trim()} title={label} aria-label={label} {...rest}>
      <Icon name={icon} size={15} />
    </button>
  );
}

export function Field({ label, hint, children, className = "" }) {
  return (
    <label className={`field ${className}`.trim()}>
      {(label || hint) && (
        <span className="field-label">
          <span>{label}</span>
          {hint && <span className="field-hint">{hint}</span>}
        </span>
      )}
      {children}
    </label>
  );
}

export function Badge({ tone = "neutral", icon, children }) {
  return (
    <span className={`badge badge-${tone}`}>
      {icon && <Icon name={icon} size={12} strokeWidth={1.9} />}
      {children}
    </span>
  );
}

export function Segmented({ options, value, onChange, disabled = false, label }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          className={value === opt.value ? "active" : ""}
          onClick={() => onChange(opt.value)}
          disabled={disabled}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

export function PageHead({ kicker, title, desc, children }) {
  return (
    <header className="page-head">
      <div>
        {kicker && <div className="kicker">{kicker}</div>}
        <h1>{title}</h1>
        {desc && <p>{desc}</p>}
      </div>
      {children && <div className="head-aside">{children}</div>}
    </header>
  );
}

export function Card({ icon, title, sub, actions, children, className = "", accent }) {
  return (
    <section className={`card ${accent ? `card-${accent}` : ""} ${className}`.trim()}>
      {(title || actions) && (
        <div className="card-head">
          {icon && (
            <span className="card-icon">
              <Icon name={icon} size={16} />
            </span>
          )}
          <div className="card-titles">
            {title && <div className="card-title">{title}</div>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, sub, tone }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone ? `tone-${tone}` : ""}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Banner({ tone = "info", children, onClose, className = "" }) {
  const iconMap = { success: "check", error: "alert", warning: "alert", info: "info" };
  return (
    <div className={`banner banner-${tone} ${className}`.trim()} role="status">
      <Icon name={iconMap[tone] || "info"} size={15} className="banner-icon" />
      <div className="banner-body">{children}</div>
      {onClose && (
        <button className="banner-close" onClick={onClose} aria-label="关闭">
          <Icon name="x" size={13} />
        </button>
      )}
    </div>
  );
}

export function EmptyState({ icon = "archive", title, desc, children }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon name={icon} size={21} />
      </div>
      {title && <h4>{title}</h4>}
      {desc && <p>{desc}</p>}
      {children && <div className="empty-actions">{children}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Toasts                                                              */
/* ------------------------------------------------------------------ */

const ToastContext = createContext(() => {});

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const notify = useCallback((tone, message) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setToasts((prev) => [...prev.slice(-3), { id, tone, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4200);
  }, []);

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={notify}>
      {children}
      <div className="toaster" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            <span className="toast-icon">
              <Icon
                name={t.tone === "success" ? "check" : t.tone === "error" ? "alert" : "info"}
                size={14}
              />
            </span>
            <span className="toast-msg">{t.message}</span>
            <button className="toast-close" onClick={() => dismiss(t.id)} aria-label="关闭">
              <Icon name="x" size={12} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
