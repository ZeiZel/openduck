declare module '@deepseek-ai/dsh-client-ui-primitives' {
  import type { ComponentType, InputHTMLAttributes, ReactNode } from 'react'
  export const Button: ComponentType<{ children?: ReactNode; disabled?: boolean; onClick?: () => void }>
  export const Input: ComponentType<InputHTMLAttributes<HTMLInputElement>>
  export const Modal: ComponentType<{ open: boolean; onClose: () => void; title: string; description?: string; children?: ReactNode; className?: string; contentClassName?: string }>
}
