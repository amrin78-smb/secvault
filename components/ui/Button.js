// Suite `.btn`/`.btn-primary`/`.btn-secondary`/`.btn-danger` classes
// (app/globals.css). `variant` keeps the same prop values callers already use.
const VARIANT_CLASS = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger: 'btn-danger',
  navy: 'btn-navy',
};

export default function Button({ variant = 'primary', className = '', children, ...props }) {
  const variantClass = VARIANT_CLASS[variant] || VARIANT_CLASS.primary;
  return (
    <button className={`btn ${variantClass} ${className}`} {...props}>
      {children}
    </button>
  );
}
