import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function fmt(value: number, digits = 2): string {
  return value.toFixed(digits)
}

export function pct(value: number, digits = 1): string {
  return (value * 100).toFixed(digits) + '%'
}
