const VARIANT_CLASSES = {
  primary: 'bg-accent text-white hover:bg-accent-hover',
  secondary: 'border border-border bg-bg-surface text-text-primary hover:bg-bg-elevated',
  danger: 'bg-danger text-white hover:opacity-90',
};

export default function Button({ variant = 'primary', className = '', children, ...props }) {
  const variantClasses = VARIANT_CLASSES[variant] || VARIANT_CLASSES.primary;

  return (
    <button
      className={`inline-flex items-center justify-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variantClasses} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
