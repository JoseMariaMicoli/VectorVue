import { ButtonHTMLAttributes } from 'react';

export function Button(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={`rounded-md bg-accent px-4 py-2 text-sm font-semibold text-black hover:opacity-90 ${props.className ?? ''}`}
    />
  );
}
