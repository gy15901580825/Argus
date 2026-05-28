import { describe, it, expect } from 'vitest'
import { cn } from '@/lib/utils'

describe('cn() — class merge helper', () => {
  it('joins string arguments', () => {
    expect(cn('a', 'b', 'c')).toBe('a b c')
  })

  it('filters out falsy values (undefined, false, null)', () => {
    expect(cn('a', undefined, false && 'nope', null, 'b')).toBe('a b')
  })

  it('applies conditional object syntax (clsx)', () => {
    expect(cn('a', { active: true, disabled: false })).toBe('a active')
  })

  it('uses tailwind-merge to dedupe conflicting utility classes (last wins)', () => {
    // Both p-2 and p-4 target the same padding property; later wins.
    expect(cn('p-2', 'p-4')).toBe('p-4')
  })

  it('preserves non-conflicting classes alongside a dedup', () => {
    expect(cn('text-red-500 p-2', 'p-4')).toBe('text-red-500 p-4')
  })
})
