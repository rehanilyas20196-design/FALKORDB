import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";

interface FieldWrapperProps {
  label: string;
  htmlFor?: string;
  required?: boolean;
  hint?: string;
  error?: string;
  children: ReactNode;
}

function FieldWrapper({
  label,
  htmlFor,
  required,
  hint,
  error,
  children,
}: FieldWrapperProps) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={htmlFor}>
        {label}
        {required ? (
          <span className="required" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      {children}
      {hint && !error ? <span className="field-hint">{hint}</span> : null}
      {error ? <span className="field-error">{error}</span> : null}
    </div>
  );
}

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  error?: string;
}

export function TextField({
  label,
  hint,
  error,
  id,
  required,
  className,
  ...rest
}: TextFieldProps) {
  const inputId = id ?? rest.name;

  return (
    <FieldWrapper
      label={label}
      htmlFor={inputId}
      required={required}
      hint={hint}
      error={error}
    >
      <input
        id={inputId}
        className={["input", className ?? ""].filter(Boolean).join(" ")}
        aria-invalid={error ? true : undefined}
        required={required}
        {...rest}
      />
    </FieldWrapper>
  );
}

interface TextAreaFieldProps
  extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  hint?: string;
  error?: string;
}

export function TextAreaField({
  label,
  hint,
  error,
  id,
  required,
  className,
  ...rest
}: TextAreaFieldProps) {
  const fieldId = id ?? rest.name;

  return (
    <FieldWrapper
      label={label}
      htmlFor={fieldId}
      required={required}
      hint={hint}
      error={error}
    >
      <textarea
        id={fieldId}
        className={["textarea", className ?? ""].filter(Boolean).join(" ")}
        aria-invalid={error ? true : undefined}
        required={required}
        {...rest}
      />
    </FieldWrapper>
  );
}

interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  hint?: string;
  error?: string;
  options: { value: string; label: string }[];
}

export function SelectField({
  label,
  hint,
  error,
  id,
  required,
  className,
  options,
  ...rest
}: SelectFieldProps) {
  const fieldId = id ?? rest.name;

  return (
    <FieldWrapper
      label={label}
      htmlFor={fieldId}
      required={required}
      hint={hint}
      error={error}
    >
      <select
        id={fieldId}
        className={["select", className ?? ""].filter(Boolean).join(" ")}
        aria-invalid={error ? true : undefined}
        required={required}
        {...rest}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </FieldWrapper>
  );
}
