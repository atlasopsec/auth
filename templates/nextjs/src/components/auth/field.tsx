"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useId, type ComponentProps } from "react";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type FieldProps = ComponentProps<"input"> & {
  name: string;
  label: string;
  error?: string;
};

// Field is a labelled input with its error, linked for screen readers.
export function Field({ name, label, error, ...props }: FieldProps) {
  // Unique on the page, even with two fields of the same name.
  const id = useId();
  const errorId = `${id}-error`;
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        name={name}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
        {...props}
      />
      {error && (
        <p id={errorId} className="text-sm text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}

// FormMessage is an error for the whole form.
export function FormMessage({ message }: { message?: string }) {
  return (
    <p role="alert" aria-live="polite" className="text-sm text-red-600">
      {message}
    </p>
  );
}
